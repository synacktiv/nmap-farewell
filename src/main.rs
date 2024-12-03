mod nfqueue;
mod nftables;
mod packets;

use std::{
    process::exit,
    sync::{
        mpsc::{channel, Receiver, RecvTimeoutError},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use nftables::{unban_everyone, unban_ip};
use packets::extract_addr_info;
use std::{collections::HashSet, net::IpAddr, time::Instant};

use crate::{nftables::ban_ip, packets::DPort};

const ALLOWED_PORTS_COUNT_BEFORE_BAN: usize = 10;
const UNBAN_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);
const UNBAN_AFTER_DURATION: Duration = Duration::from_secs(12 * 60 * 60);
const AMOUNT_OF_QUEUES_TO_LISTEN_TO: u16 = 4;

#[derive(Debug)]
struct SuspiciousClient {
    addr: IpAddr,
    reached_ports: HashSet<DPort>,
    ban_instant: Option<Instant>,
}

impl SuspiciousClient {
    fn new(addr: IpAddr) -> Self {
        Self {
            addr,
            reached_ports: HashSet::new(),
            ban_instant: None,
        }
    }
}

/// To be able to stop threads cleanly.
enum WakeUp<T> {
    DataAvailable(T),
    MustExitNow,
}

fn main() {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .filter_module("rustables", log::LevelFilter::Warn)
        .init();

    // Unban everyone on daemon start, to prevent stale bans
    if let Err(err) = unban_everyone() {
        log::error!("Failed to unban everyone: {err} (permission issue ?)");
    }

    let (packet_wakeup_sender, packet_wakeup_receiver) = channel();
    let (unban_wakeup_sender, unban_wakeup_receiver) = channel();
    let (packets_sender, packets_receiver) = channel();

    let suspicious_clients: Arc<Mutex<Vec<SuspiciousClient>>> = Arc::new(Mutex::new(Vec::new()));
    let suspicious_clients_clone = suspicious_clients.clone();

    let handle_packet_thread =
        thread::spawn(move || handle_packet_thread(suspicious_clients, packet_wakeup_receiver));
    let unban_thread =
        thread::spawn(move || unban_thread(suspicious_clients_clone, unban_wakeup_receiver));

    let mut queue_listen_threads = Vec::new();

    for i in 0..AMOUNT_OF_QUEUES_TO_LISTEN_TO {
        let sender = packets_sender.clone();
        queue_listen_threads.push(thread::spawn(move || nfqueue::listen(i, sender)));
    }

    // Main loop of the program, retrieve packets from all the queues,
    // but also monitors threads to make sure they don't stop/panic, if one of them do,
    // we tell the other threads to stop as well and we exit the program cleanly.
    loop {
        match packets_receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(packet) => packet_wakeup_sender
                .send(WakeUp::DataAvailable(packet))
                .expect("packet_wakeup channel is dead"),
            Err(err) => match err {
                RecvTimeoutError::Timeout => {}
                RecvTimeoutError::Disconnected => panic!("packets channel is dead"),
            },
        }

        if handle_packet_thread.is_finished()
            || unban_thread.is_finished()
            || queue_listen_threads.iter().any(|t| t.is_finished())
        {
            // NOTE: the nfqueue::listen() threads cannot be stopped cleanly because they are blocking.
            packet_wakeup_sender
                .send(WakeUp::MustExitNow)
                .expect("WakeUp channel is dead");

            unban_wakeup_sender
                .send(WakeUp::MustExitNow)
                .expect("WakeUp channel is dead");
            break;
        }
    }

    if let Err(err) = unban_thread.join() {
        let panic_msg = err
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| err.downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("unknown reason");

        log::error!("Unban thread panicked: {panic_msg}");
    }

    let join_result = handle_packet_thread.join();
    if let Err(err) = join_result {
        let panic_msg = err
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| err.downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("unknown reason");

        log::error!("Packets handling thread panicked: {panic_msg}");
    }

    for listen_thread in queue_listen_threads {
        // NOTE: we do not join nfqueue::listen() threads that didn't finish
        // because they are blocking and cannot be stopped cleanly.
        if listen_thread.is_finished() {
            let join_result = listen_thread.join();

            if let Err(err) = join_result {
                let panic_msg = err
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| err.downcast_ref::<String>().map(|s| s.as_str()))
                    .unwrap_or("unknown reason");

                log::error!("Listen queue thread panicked: {panic_msg}");
            } else if let Ok(Err(err)) = join_result {
                log::error!("Listen queue thread exited with error: {err}");
            }
        }
    }

    exit(1);
}

fn handle_packet_thread(
    suspicious_clients: Arc<Mutex<Vec<SuspiciousClient>>>,
    wake_up_receiver: Receiver<WakeUp<Vec<u8>>>,
) -> anyhow::Result<()> {
    loop {
        let packet = match wake_up_receiver.recv()? {
            WakeUp::DataAvailable(packet) => packet,
            WakeUp::MustExitNow => return Ok(()),
        };

        match extract_addr_info(&packet) {
            Ok((addr, port)) => {
                handle_suspicious_client(suspicious_clients.clone(), addr, port);
            }
            Err(err) => {
                log::debug!("Unable to process packet: {err}");
            }
        }
    }
}

fn unban_thread(
    suspicious_clients: Arc<Mutex<Vec<SuspiciousClient>>>,
    wake_up_receiver: Receiver<WakeUp<()>>,
) -> anyhow::Result<()> {
    loop {
        log::trace!("unban thread going to sleep...");

        if let WakeUp::MustExitNow = wake_up_receiver.recv_timeout(UNBAN_CHECK_INTERVAL)? {
            return Ok(());
        }

        let now = Instant::now();

        let clients = suspicious_clients.lock().expect("unable to acquire mutex");
        let mut clients_to_unban: Vec<&SuspiciousClient> = clients
            .iter()
            .filter(|c| {
                c.ban_instant
                    .is_some_and(|ban_instant| now - ban_instant > UNBAN_AFTER_DURATION)
            })
            .collect();

        log::debug!("There are {} clients to unban", clients_to_unban.len());

        clients_to_unban.retain(|client| match unban_ip(client.addr) {
            Ok(_) => {
                log::info!("{} has been unbanned", client.addr);
                true
            }
            Err(err) => {
                log::error!("unban_suspicious_client failed: {err}");
                false
            }
        });
    }
}

fn handle_suspicious_client(
    suspicious_clients: Arc<Mutex<Vec<SuspiciousClient>>>,
    client_addr: IpAddr,
    client_reached_port: DPort,
) {
    log::trace!(
        "handle_suspicious_client(suspicious_clients, {client_addr}, {client_reached_port});"
    );
    let mut existing_suspicious_clients =
        suspicious_clients.lock().expect("unable to acquire mutex");

    let existing_client = existing_suspicious_clients
        .iter_mut()
        .find(|c| c.addr == client_addr);

    if existing_client
        .as_ref()
        .is_some_and(|c| c.ban_instant.is_some())
    {
        log::debug!(
            "{client_addr} is banned already, can happen when multiple packets were queued"
        );
        return;
    }

    let client = match existing_client {
        Some(existing_client) => existing_client,
        None => {
            existing_suspicious_clients.push(SuspiciousClient::new(client_addr));
            existing_suspicious_clients
                .last_mut()
                .expect("push to vec failed ? that should not happen")
        }
    };

    client.reached_ports.insert(client_reached_port);
    log::debug!("{client:?}");

    if client.reached_ports.len() >= ALLOWED_PORTS_COUNT_BEFORE_BAN {
        match ban_ip(client.addr) {
            Ok(()) => {
                client.ban_instant = Some(Instant::now());
                log::info!("{client_addr} has been banned");
            }
            Err(err) => {
                // If the ban didn't succeed, we keep the suspicious client in the vec for later retry
                log::error!("Failed to ban client: {err}");
            }
        }
    }
}

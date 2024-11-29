use std::sync::mpsc::Sender;

pub(crate) fn listen(queue_id: u16, packets_sender: Sender<Vec<u8>>) -> anyhow::Result<()> {
    log::trace!("listen({queue_id}, packet_handler_callback)");

    let mut queue = nfq::Queue::open()?;
    queue.bind(queue_id)?;
    log::info!("Listening to queue {queue_id}");

    loop {
        let mut msg = queue.recv()?;
        let packet = msg.get_payload().to_vec();

        log::debug!(
            "Got new packet of {} bytes from queue {queue_id}",
            packet.len()
        );

        // Send the packet to our handling thread, so that we issue a verdict faster.
        packets_sender.send(packet)?;

        msg.set_verdict(nfq::Verdict::Drop);
        queue.verdict(msg)?;
    }
}

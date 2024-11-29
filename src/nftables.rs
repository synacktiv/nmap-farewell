use anyhow::anyhow;
use rustables::{
    expr::{CmpOp, ExpressionVariant, MetaType, RawExpression, Register, Verdict, VerdictType},
    Batch, Chain, Hook, HookClass, ProtocolFamily, Rule, Table,
};
use std::net::IpAddr;

const NETFILTER_TABLE_NAME: &str = "port_scanners_auto_ban";
const NETFILTER_CHAIN_NAME: &str = "prerouting";
const NETFILTER_HOOK_PRIORITY: i32 = libc::NF_IP_PRI_RAW_BEFORE_DEFRAG;

pub(crate) fn ban_ip(addr: IpAddr) -> anyhow::Result<()> {
    log::trace!("ban_ip({addr})");

    let mut batch = Batch::new();
    let chain = get_chain_or_create(&mut batch)?;

    Rule::new(&chain)?
        .match_ip(addr, true)
        .drop()
        .add_to_batch(&mut batch);

    batch.send()?;

    Ok(())
}

pub(crate) fn unban_ip(addr: IpAddr) -> anyhow::Result<()> {
    log::trace!("unban_ip({addr})");

    let addr_octets = match addr {
        IpAddr::V4(ipv4_addr) => ipv4_addr.octets().to_vec(),
        IpAddr::V6(ipv6_addr) => ipv6_addr.octets().to_vec(),
    };

    let mut batch = Batch::new();
    let chain = get_chain_or_create(&mut batch)?;
    let rules = rustables::list_rules_for_chain(&chain)?;

    let mut rule_to_remove: Option<Rule> = None;

    for rule in rules {
        let handle = match rule.get_handle() {
            Some(handle) => *handle,
            None => {
                log::error!("Rule does not have any handle ?!");
                continue;
            }
        };

        let exprs = match rule.get_expressions() {
            Some(exprs) => exprs,
            None => {
                log::error!("Rule does not have any expression ?!");
                continue;
            }
        };

        // Make sure the current rule is the one we are looking for by checking various inner expressions
        let mut found_nf_proto = false;
        let mut found_ip_cmp = false;
        let mut found_ip = false;
        let mut found_drop = false;

        for expr in exprs.iter() {
            match expr.get_data() {
                Some(ExpressionVariant::Meta(meta)) => {
                    if meta.get_key().is_some_and(|k| *k == MetaType::NfProto) {
                        found_nf_proto = true;
                    }
                }
                Some(ExpressionVariant::Cmp(cmp)) => {
                    if cmp.get_op().is_some_and(|op| *op == CmpOp::Eq) {
                        if let Some(data) = cmp.get_data() {
                            if let Some(value) = data.get_value() {
                                if value.contains(&(libc::NFPROTO_IPV4 as u8))
                                    || value.contains(&(libc::NFPROTO_IPV6 as u8))
                                {
                                    found_ip_cmp = true;
                                }

                                if *value == addr_octets {
                                    found_ip = true;
                                }
                            }
                        }
                    }
                }
                Some(ExpressionVariant::Immediate(imm)) => {
                    if imm.get_dreg() == Some(&Register::Verdict)
                        && imm.get_data().and_then(|d| d.get_verdict())
                            == Some(&Verdict::default().with_code(VerdictType::Drop))
                    {
                        found_drop = true;
                    }
                }

                _ => {}
            }
        }

        if found_nf_proto && found_ip_cmp && found_ip && found_drop {
            rule_to_remove = Some(Rule::new(&chain)?.with_handle(handle));
            break;
        }
    }

    if let Some(rule_to_remove) = rule_to_remove {
        let mut batch = Batch::new();
        batch.add(&rule_to_remove, rustables::MsgType::Del);
        batch.send()?;
        Ok(())
    } else {
        Err(anyhow!("banned IP not found"))
    }
}

pub(crate) fn unban_everyone() -> anyhow::Result<()> {
    log::trace!("unban_everyone()");

    let mut batch = Batch::new();
    let chain = get_chain_or_create(&mut batch)?;
    let rules = rustables::list_rules_for_chain(&chain)?;
    let mut rules_to_remove: Vec<Rule> = Vec::new();

    for rule in rules {
        let handle = match rule.get_handle() {
            Some(handle) => *handle,
            None => {
                log::error!("Rule does not have any handle ?!");
                continue;
            }
        };

        let exprs = match rule.get_expressions() {
            Some(exprs) => exprs,
            None => {
                log::error!("Rule does not have any expression ?!");
                continue;
            }
        };

        // Make sure the current rule is the one we are looking for by checking various inner expressions
        let mut found_nf_proto = false;
        let mut found_ip_cmp = false;
        let mut found_ip = false;
        let mut found_drop = false;

        let expressions: Vec<&RawExpression> = exprs.iter().collect();

        for expr in expressions {
            match expr.get_data() {
                Some(ExpressionVariant::Meta(meta)) => {
                    if meta.get_key().is_some_and(|k| *k == MetaType::NfProto) {
                        found_nf_proto = true;
                    }
                }
                Some(ExpressionVariant::Cmp(cmp)) => {
                    if cmp.get_op().is_some_and(|op| *op == CmpOp::Eq) {
                        if let Some(data) = cmp.get_data() {
                            if let Some(value) = data.get_value() {
                                let ipv4: Result<[u8; 4], _> = value.as_slice().try_into();
                                let ipv6: Result<[u8; 16], _> = value.as_slice().try_into();

                                if ipv4.is_ok() || ipv6.is_ok() {
                                    found_ip = true;
                                }

                                if value.contains(&(libc::NFPROTO_IPV4 as u8))
                                    || value.contains(&(libc::NFPROTO_IPV6 as u8))
                                {
                                    found_ip_cmp = true;
                                }
                            }
                        }
                    }
                }
                Some(ExpressionVariant::Immediate(imm)) => {
                    if imm.get_dreg() == Some(&Register::Verdict)
                        && imm.get_data().and_then(|d| d.get_verdict())
                            == Some(&Verdict::default().with_code(VerdictType::Drop))
                    {
                        found_drop = true;
                    }
                }

                _ => {}
            }
        }

        if found_nf_proto && found_ip_cmp && found_ip && found_drop {
            rules_to_remove.push(Rule::new(&chain)?.with_handle(handle));
        }
    }

    if !rules_to_remove.is_empty() {
        let mut batch = Batch::new();

        for rule in rules_to_remove {
            batch.add(&rule, rustables::MsgType::Del);
        }

        batch.send()?;
    }

    Ok(())
}

fn get_chain_or_create(batch: &mut Batch) -> anyhow::Result<Chain> {
    let mut tables = rustables::list_tables()?;
    let existing_table_index = tables.iter().position(|t| {
        t.get_name()
            .is_some_and(|name| name == NETFILTER_TABLE_NAME)
    });

    let table = match existing_table_index {
        // By removing the value from the vec, we take ownership of it
        Some(index) => tables.remove(index),
        None => Table::new(ProtocolFamily::Inet)
            .with_name(NETFILTER_TABLE_NAME)
            .add_to_batch(batch),
    };

    let mut chains = rustables::list_chains_for_table(&table)?;
    let existing_chain_index = chains.iter().position(|c| {
        c.get_name()
            .is_some_and(|name| name == NETFILTER_CHAIN_NAME)
    });

    let chain = match existing_chain_index {
        // By removing the value from the vec, we take ownership of it
        Some(index) => chains.remove(index),
        None => Chain::new(&table)
            .with_name(NETFILTER_CHAIN_NAME)
            .with_hook(Hook::new(HookClass::PreRouting, NETFILTER_HOOK_PRIORITY))
            .add_to_batch(batch),
    };

    Ok(chain)
}

// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::neighborhood::overall_connection_status::ConnectionStageErrors::{
    DeadEndFound, NoGossipResponseReceived, TcpConnectionFailed,
};
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::neighborhood::{ConnectionProgressEvent, NodeDescriptor};
use openssl::init;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;

#[derive(PartialEq, Debug, Clone)]
pub enum ConnectionStageErrors {
    TcpConnectionFailed,
    NoGossipResponseReceived,
    DeadEndFound,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ConnectionStage {
    StageZero,
    TcpConnectionEstablished,
    NeighborshipEstablished,
    Failed(ConnectionStageErrors),
}

impl TryFrom<&ConnectionStage> for usize {
    type Error = ();

    fn try_from(connection_stage: &ConnectionStage) -> Result<Self, Self::Error> {
        match connection_stage {
            ConnectionStage::StageZero => Ok(0),
            ConnectionStage::TcpConnectionEstablished => Ok(1),
            ConnectionStage::NeighborshipEstablished => Ok(2),
            ConnectionStage::Failed(_) => Err(()),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct ConnectionProgress {
    pub initial_node_descriptor: NodeDescriptor,
    pub current_peer_addr: IpAddr,
    pub connection_stage: ConnectionStage,
}

impl ConnectionProgress {
    pub fn new(node_descriptor: &NodeDescriptor) -> Self {
        let node_addr = node_descriptor.node_addr_opt.as_ref().unwrap_or_else(|| {
            panic!(
                "Unable to receive node addr for the descriptor {:?}",
                node_descriptor
            )
        });
        Self {
            initial_node_descriptor: node_descriptor.clone(),
            current_peer_addr: node_addr.ip_addr(),
            connection_stage: ConnectionStage::StageZero,
        }
    }

    pub fn update_stage(&mut self, connection_stage: ConnectionStage) {
        let current_stage = usize::try_from((&self.connection_stage));
        let new_stage = usize::try_from((&connection_stage));

        if let (Ok(current_stage_num), Ok(new_stage_num)) = (current_stage, new_stage) {
            if new_stage_num != current_stage_num + 1 {
                panic!(
                    "Can't update the stage from {:?} to {:?}",
                    self.connection_stage, connection_stage
                )
            }
        }

        self.connection_stage = connection_stage;
    }

    pub fn handle_pass_gossip(&mut self, new_pass_target: IpAddr) {
        if self.connection_stage != ConnectionStage::TcpConnectionEstablished {
            panic!(
                "Can't update the stage from {:?} to {:?}",
                self.connection_stage,
                ConnectionStage::StageZero
            )
        };

        self.connection_stage = ConnectionStage::StageZero;
        self.current_peer_addr = new_pass_target;
    }
}

#[derive(PartialEq, Debug)]
enum OverallConnectionStage {
    NotConnected,        // Not connected to any neighbor.
    ConnectedToNeighbor, // Neighborship established. Same as No 3 hops route found.
    ThreeHopsRouteFound, // check_connectedness() returned true, data can now be relayed.
}

// TODO: Migrate this struct and code related to it to a new module and make that module public only for neighborhood
#[derive(PartialEq, Debug)]
pub struct OverallConnectionStatus {
    // Becomes true iff three hops route was found.
    can_make_routes: bool,
    // Stores one of the three stages of enum OverallConnectionStage.
    stage: OverallConnectionStage,
    // Corresponds to progress with node descriptors entered by the user
    pub progress: Vec<ConnectionProgress>,
}

impl OverallConnectionStatus {
    pub fn new(initial_node_descriptors: Vec<NodeDescriptor>) -> Self {
        let progress = initial_node_descriptors
            .iter()
            .map(|node_descriptor| ConnectionProgress::new(&node_descriptor))
            .collect();

        Self {
            can_make_routes: false,
            stage: OverallConnectionStage::NotConnected,
            progress,
        }
    }

    pub fn iter_initial_node_descriptors(&self) -> impl Iterator<Item = &NodeDescriptor> {
        self.progress
            .iter()
            .map(|connection_progress| &connection_progress.initial_node_descriptor)
    }

    pub fn get_connection_progress_by_ip(&mut self, peer_addr: IpAddr) -> &mut ConnectionProgress {
        let mut connection_progress_to_modify = self
            .progress
            .iter_mut()
            .find(|connection_progress| connection_progress.current_peer_addr == peer_addr)
            .unwrap_or_else(|| {
                panic!(
                    "Unable to find the node in connections with IP Address: {}",
                    peer_addr
                )
            });

        connection_progress_to_modify
    }

    pub fn get_connection_progress_by_desc(
        &self,
        initial_node_descriptor: &NodeDescriptor,
    ) -> &ConnectionProgress {
        let connection_progress = self
            .progress
            .iter()
            .find(|connection_progress| {
                &connection_progress.initial_node_descriptor == initial_node_descriptor
            })
            .unwrap_or_else(|| {
                panic!(
                    "Unable to find the node in connections with Node Descriptor: {:?}",
                    initial_node_descriptor
                )
            });

        connection_progress
    }

    pub fn update_connection_stage(&mut self, peer_addr: IpAddr, event: ConnectionProgressEvent) {
        let mut connection_progress_to_modify = self.get_connection_progress_by_ip(peer_addr);

        match event {
            ConnectionProgressEvent::TcpConnectionSuccessful => connection_progress_to_modify
                .update_stage(ConnectionStage::TcpConnectionEstablished),

            ConnectionProgressEvent::TcpConnectionFailed => connection_progress_to_modify
                .update_stage(ConnectionStage::Failed(TcpConnectionFailed)),

            ConnectionProgressEvent::IntroductionGossipReceived(new_node) => {
                connection_progress_to_modify
                    .update_stage(ConnectionStage::NeighborshipEstablished);
                self.update_stage_of_overall_connection_status();
            }
            ConnectionProgressEvent::StandardGossipReceived => {
                connection_progress_to_modify
                    .update_stage(ConnectionStage::NeighborshipEstablished);
                self.update_stage_of_overall_connection_status();
            }
            ConnectionProgressEvent::PassGossipReceived(new_pass_target) => {
                connection_progress_to_modify.handle_pass_gossip(new_pass_target);
            }
            ConnectionProgressEvent::DeadEndFound => {
                connection_progress_to_modify.update_stage(ConnectionStage::Failed(DeadEndFound));
            }
            ConnectionProgressEvent::NoGossipResponseReceived => {
                connection_progress_to_modify
                    .update_stage(ConnectionStage::Failed(NoGossipResponseReceived));
            }
        }
    }

    fn update_stage_of_overall_connection_status(&mut self) {
        // For now, this function is only called when Standard or Introduction Gossip
        // is received,
        // TODO: Write a more generalized fn, which can be called when any stage gets updated

        if self.can_make_routes() {
            self.stage = OverallConnectionStage::ThreeHopsRouteFound;
        } else {
            self.stage = OverallConnectionStage::ConnectedToNeighbor;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.progress.is_empty()
    }

    pub fn remove(&mut self, index: usize) -> NodeDescriptor {
        let removed_connection_progress = self.progress.remove(index);
        removed_connection_progress.initial_node_descriptor
    }

    pub fn can_make_routes(&self) -> bool {
        self.can_make_routes
    }

    pub fn update_can_make_routes(&mut self, can_make_routes: bool) {
        self.can_make_routes = can_make_routes;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighborhood::overall_connection_status::ConnectionStageErrors::{
        DeadEndFound, TcpConnectionFailed,
    };
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::test_utils::main_cryptde;
    use masq_lib::blockchains::chains::Chain;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    #[test]
    #[should_panic(
        expected = "Unable to receive node addr for the descriptor NodeDescriptor { blockchain: EthRopsten, encryption_public_key: AAAA, node_addr_opt: None }"
    )]
    fn can_not_create_a_new_connection_without_node_addr() {
        let descriptor_with_no_ip_address = NodeDescriptor {
            blockchain: Chain::EthRopsten,
            encryption_public_key: PublicKey::from(vec![0, 0, 0]),
            node_addr_opt: None, // NodeAddr consists of IP Address and Ports
        };
        let connection_progress = ConnectionProgress::new(&descriptor_with_no_ip_address);
    }

    #[test]
    fn connection_progress_handles_pass_gossip_correctly() {
        let ip_addr = IpAddr::from_str("1.2.3.4").unwrap();
        let initial_node_descriptor = make_node_descriptor_from_ip(ip_addr);
        let mut subject = ConnectionProgress::new(&initial_node_descriptor);
        let new_pass_target_ip_addr = IpAddr::from_str("5.6.7.8").unwrap();
        subject.update_stage(ConnectionStage::TcpConnectionEstablished);

        subject.handle_pass_gossip(new_pass_target_ip_addr);

        assert_eq!(
            subject,
            ConnectionProgress {
                initial_node_descriptor,
                current_peer_addr: new_pass_target_ip_addr,
                connection_stage: ConnectionStage::StageZero
            }
        )
    }

    #[test]
    #[should_panic(expected = "Can't update the stage from StageZero to StageZero")]
    fn connection_progress_panics_while_handling_pass_gossip_in_case_tcp_connection_is_not_established(
    ) {
        let ip_addr = IpAddr::from_str("1.2.3.4").unwrap();
        let initial_node_descriptor = make_node_descriptor_from_ip(ip_addr);
        let mut subject = ConnectionProgress::new(&initial_node_descriptor);
        let new_pass_target_ip_addr = IpAddr::from_str("5.6.7.8").unwrap();

        subject.handle_pass_gossip(new_pass_target_ip_addr);
    }

    #[test]
    fn able_to_create_overall_connection_status() {
        let node_desc_1 = NodeDescriptor::try_from((
            main_cryptde(), // Used to provide default cryptde
            "masq://eth-ropsten:AQIDBA@1.2.3.4:1234/2345",
        ))
        .unwrap();
        let node_desc_2 = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:AgMEBQ@1.2.3.5:1234/2345",
        ))
        .unwrap();
        let initial_node_descriptors = vec![node_desc_1.clone(), node_desc_2.clone()];

        let subject = OverallConnectionStatus::new(initial_node_descriptors);

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![
                    ConnectionProgress::new(&node_desc_1),
                    ConnectionProgress::new(&node_desc_2)
                ],
            }
        );
    }

    #[test]
    fn overall_connection_status_identifies_as_empty() {
        let subject = OverallConnectionStatus::new(vec![]);

        assert_eq!(subject.is_empty(), true);
    }

    #[test]
    fn overall_connection_status_identifies_as_non_empty() {
        let node_desc = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:AQIDBA@1.2.3.4:1234/2345",
        ))
        .unwrap();

        let initial_node_descriptors = vec![node_desc.clone()];

        let subject = OverallConnectionStatus::new(initial_node_descriptors);

        assert_eq!(subject.is_empty(), false);
    }

    #[test]
    fn can_receive_mut_ref_of_connection_progress_from_peer_addr() {
        let peer_1_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let peer_2_ip = IpAddr::from_str("5.6.7.8").unwrap();
        let peer_3_ip = IpAddr::from_str("9.0.1.2").unwrap();

        let desc_1 = make_node_descriptor_from_ip(peer_1_ip);
        let desc_2 = make_node_descriptor_from_ip(peer_2_ip);
        let desc_3 = make_node_descriptor_from_ip(peer_3_ip);

        let initial_node_descriptors = vec![desc_1.clone(), desc_2.clone(), desc_3.clone()];

        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        assert_eq!(
            subject.get_connection_progress_by_ip(peer_1_ip),
            &mut ConnectionProgress::new(&desc_1)
        );
        assert_eq!(
            subject.get_connection_progress_by_ip(peer_2_ip),
            &mut ConnectionProgress::new(&desc_2)
        );
        assert_eq!(
            subject.get_connection_progress_by_ip(peer_3_ip),
            &mut ConnectionProgress::new(&desc_3)
        );
    }

    #[test]
    fn can_receive_connection_progress_from_initial_node_desc() {
        let desc_1 = make_node_descriptor_from_ip(IpAddr::from_str("1.2.3.4").unwrap());
        let desc_2 = make_node_descriptor_from_ip(IpAddr::from_str("5.6.7.8").unwrap());
        let desc_3 = make_node_descriptor_from_ip(IpAddr::from_str("9.0.1.2").unwrap());

        let initial_node_descriptors = vec![desc_1.clone(), desc_2.clone(), desc_3.clone()];

        let subject = OverallConnectionStatus::new(initial_node_descriptors);

        assert_eq!(
            subject.get_connection_progress_by_desc(&desc_1),
            &ConnectionProgress::new(&desc_1)
        );
        assert_eq!(
            subject.get_connection_progress_by_desc(&desc_2),
            &ConnectionProgress::new(&desc_2)
        );
        assert_eq!(
            subject.get_connection_progress_by_desc(&desc_1),
            &ConnectionProgress::new(&desc_1)
        );
    }

    #[test]
    fn starting_descriptors_are_iterable() {
        let node_desc_1 = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:AQIDBA@1.2.3.4:1234/2345",
        ))
        .unwrap();
        let node_desc_2 = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:AgMEBQ@1.2.3.5:1234/2345",
        ))
        .unwrap();
        let initial_node_descriptors = vec![node_desc_1.clone(), node_desc_2.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        let mut result = subject.iter_initial_node_descriptors();

        assert_eq!(result.next(), Some(&node_desc_1));
        assert_eq!(result.next(), Some(&node_desc_2));
        assert_eq!(result.next(), None);
    }

    #[test]
    fn remove_deletes_descriptor_s_progress_and_returns_node_descriptor() {
        let node_desc_1 = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:AQIDBA@1.2.3.4:1234/2345",
        ))
        .unwrap();
        let node_desc_2 = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:AgMEBQ@1.2.3.5:1234/2345",
        ))
        .unwrap();
        let initial_node_descriptors = vec![node_desc_1.clone(), node_desc_2.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        let removed_desc_1 = subject.remove(0);
        let removed_desc_2 = subject.remove(0);

        assert_eq!(removed_desc_1, node_desc_1);
        assert_eq!(removed_desc_2, node_desc_2);
        assert_eq!(subject, OverallConnectionStatus::new(vec![]));
    }

    #[test]
    fn updates_the_connection_stage_to_tcp_connection_established() {
        let node_ip_addr: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let node_decriptor = NodeDescriptor {
            blockchain: Chain::EthRopsten,
            encryption_public_key: PublicKey::from(vec![0, 0, 0]),
            node_addr_opt: Some(NodeAddr::new(&node_ip_addr, &vec![1, 2, 3])),
        };
        let initial_node_descriptors = vec![node_decriptor.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        subject.update_connection_stage(
            node_decriptor.node_addr_opt.as_ref().unwrap().ip_addr(),
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![ConnectionProgress {
                    initial_node_descriptor: node_decriptor.clone(),
                    current_peer_addr: node_ip_addr,
                    connection_stage: ConnectionStage::TcpConnectionEstablished
                }],
            }
        )
    }

    #[test]
    fn updates_the_connection_stage_to_failed_when_tcp_connection_fails() {
        let node_ip_addr: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let node_decriptor = NodeDescriptor {
            blockchain: Chain::EthRopsten,
            encryption_public_key: PublicKey::from(vec![0, 0, 0]),
            node_addr_opt: Some(NodeAddr::new(&node_ip_addr, &vec![1, 2, 3])),
        };
        let initial_node_descriptors = vec![node_decriptor.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        subject.update_connection_stage(
            node_ip_addr.clone(),
            ConnectionProgressEvent::TcpConnectionFailed,
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![ConnectionProgress {
                    initial_node_descriptor: node_decriptor.clone(),
                    current_peer_addr: node_ip_addr,
                    connection_stage: ConnectionStage::Failed(TcpConnectionFailed)
                }],
            }
        )
    }

    #[test]
    fn updates_the_connection_stage_to_neighborship_established() {
        let node_ip_addr: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let node_descriptor = make_node_descriptor_from_ip(node_ip_addr);
        let initial_node_descriptors = vec![node_descriptor.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);
        let new_node_ip_addr: IpAddr = Ipv4Addr::new(5, 6, 7, 8).into();
        subject.update_connection_stage(
            node_ip_addr,
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );

        subject.update_connection_stage(
            node_ip_addr,
            ConnectionProgressEvent::IntroductionGossipReceived(new_node_ip_addr),
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::ConnectedToNeighbor,
                progress: vec![ConnectionProgress {
                    initial_node_descriptor: node_descriptor.clone(),
                    current_peer_addr: node_ip_addr,
                    connection_stage: ConnectionStage::NeighborshipEstablished
                }],
            }
        )
    }

    #[test]
    fn updates_the_connection_stage_to_neighborship_established_when_standard_gossip_is_received() {
        let node_ip_addr: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let node_descriptor = make_node_descriptor_from_ip(node_ip_addr);
        let initial_node_descriptors = vec![node_descriptor.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);
        let new_node_ip_addr: IpAddr = Ipv4Addr::new(5, 6, 7, 8).into();
        subject.update_connection_stage(
            node_ip_addr,
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );

        subject.update_connection_stage(
            node_ip_addr,
            ConnectionProgressEvent::StandardGossipReceived,
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::ConnectedToNeighbor,
                progress: vec![ConnectionProgress {
                    initial_node_descriptor: node_descriptor.clone(),
                    current_peer_addr: node_ip_addr,
                    connection_stage: ConnectionStage::NeighborshipEstablished
                }],
            }
        )
    }

    #[test]
    fn updates_the_connection_stage_to_stage_zero_when_pass_gossip_is_received() {
        let node_ip_addr: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let node_descriptor = make_node_descriptor_from_ip(node_ip_addr);
        let initial_node_descriptors = vec![node_descriptor.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);
        let new_node_ip_addr: IpAddr = Ipv4Addr::new(5, 6, 7, 8).into();
        subject.update_connection_stage(
            node_ip_addr,
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );

        subject.update_connection_stage(
            node_ip_addr,
            ConnectionProgressEvent::PassGossipReceived(new_node_ip_addr),
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![ConnectionProgress {
                    initial_node_descriptor: node_descriptor.clone(),
                    current_peer_addr: new_node_ip_addr,
                    connection_stage: ConnectionStage::StageZero
                }],
            }
        )
    }

    #[test]
    fn updates_connection_stage_to_failed_when_dead_end_is_found() {
        let node_ip_addr: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let node_descriptor = make_node_descriptor_from_ip(node_ip_addr);
        let initial_node_descriptors = vec![node_descriptor.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);
        let new_node_ip_addr: IpAddr = Ipv4Addr::new(5, 6, 7, 8).into();
        subject.update_connection_stage(
            node_ip_addr,
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );

        subject.update_connection_stage(node_ip_addr, ConnectionProgressEvent::DeadEndFound);

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![ConnectionProgress {
                    initial_node_descriptor: node_descriptor.clone(),
                    current_peer_addr: node_ip_addr,
                    connection_stage: ConnectionStage::Failed(DeadEndFound)
                }],
            }
        )
    }

    #[test]
    fn updates_connection_stage_to_failed_when_no_gossip_response_is_received() {
        let node_ip_addr: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let node_descriptor = make_node_descriptor_from_ip(node_ip_addr);
        let initial_node_descriptors = vec![node_descriptor.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);
        let new_node_ip_addr: IpAddr = Ipv4Addr::new(5, 6, 7, 8).into();
        subject.update_connection_stage(
            node_ip_addr,
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );

        subject.update_connection_stage(
            node_ip_addr,
            ConnectionProgressEvent::NoGossipResponseReceived,
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![ConnectionProgress {
                    initial_node_descriptor: node_descriptor.clone(),
                    current_peer_addr: node_ip_addr,
                    connection_stage: ConnectionStage::Failed(NoGossipResponseReceived)
                }],
            }
        )
    }

    #[test]
    #[should_panic(expected = "Unable to find the node in connections with IP Address: 5.6.7.8")]
    fn panics_at_updating_the_connection_stage_if_a_node_is_not_a_part_of_connections() {
        let node_ip_addr: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let node_decriptor = NodeDescriptor {
            blockchain: Chain::EthRopsten,
            encryption_public_key: PublicKey::from(vec![0, 0, 0]),
            node_addr_opt: Some(NodeAddr::new(&node_ip_addr, &vec![1, 2, 3])),
        };
        let initial_node_descriptors = vec![node_decriptor.clone()];
        let non_existing_node_s_ip_addr: IpAddr = Ipv4Addr::new(5, 6, 7, 8).into();
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        subject.update_connection_stage(
            non_existing_node_s_ip_addr,
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );
    }

    #[test]
    fn connection_stage_can_be_converted_to_number() {
        assert_eq!(usize::try_from(&ConnectionStage::StageZero), Ok(0));
        assert_eq!(
            usize::try_from(&ConnectionStage::TcpConnectionEstablished),
            Ok(1)
        );
        assert_eq!(
            usize::try_from(&ConnectionStage::NeighborshipEstablished),
            Ok(2)
        );
        assert_eq!(
            usize::try_from(&ConnectionStage::Failed(TcpConnectionFailed)),
            Err(())
        );
    }

    #[test]
    #[should_panic(expected = "Can't update the stage from StageZero to NeighborshipEstablished")]
    fn can_t_establish_neighborhsip_without_having_a_tcp_connection() {
        let node_ip_addr: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let node_decriptor = NodeDescriptor {
            blockchain: Chain::EthRopsten,
            encryption_public_key: PublicKey::from(vec![0, 0, 0]),
            node_addr_opt: Some(NodeAddr::new(&node_ip_addr, &vec![1, 2, 3])),
        };
        let new_node_ip_addr: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let initial_node_descriptors = vec![node_decriptor.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        subject.update_connection_stage(
            node_ip_addr,
            ConnectionProgressEvent::IntroductionGossipReceived(new_node_ip_addr),
        );
    }

    #[test]
    fn getter_fn_exists_for_boolean_can_make_routes() {
        let ip_addr = IpAddr::from_str("1.2.3.4").unwrap();
        let initial_node_descriptor = make_node_descriptor_from_ip(ip_addr);
        let subject = OverallConnectionStatus::new(vec![initial_node_descriptor]);

        let can_make_routes = subject.can_make_routes();

        assert_eq!(can_make_routes, false);
    }

    #[test]
    fn can_update_the_boolean_can_make_routes() {
        let ip_addr = IpAddr::from_str("1.2.3.4").unwrap();
        let initial_node_descriptor = make_node_descriptor_from_ip(ip_addr);
        let mut subject = OverallConnectionStatus::new(vec![initial_node_descriptor]);
        let can_make_routes_initially = subject.can_make_routes();

        subject.update_can_make_routes(true);

        let can_make_routes_finally = subject.can_make_routes();
        assert_eq!(can_make_routes_initially, false);
        assert_eq!(can_make_routes_finally, true);
    }

    #[test]
    fn updates_from_not_connected_to_connected_to_neighbor_in_case_flag_is_false() {
        let ip_addr = IpAddr::from_str("1.2.3.4").unwrap();
        let initial_node_descriptor = make_node_descriptor_from_ip(ip_addr);
        let mut subject = OverallConnectionStatus::new(vec![initial_node_descriptor]);
        subject.update_can_make_routes(false);

        subject.update_stage_of_overall_connection_status();

        assert_eq!(subject.stage, OverallConnectionStage::ConnectedToNeighbor);
    }

    #[test]
    fn updates_from_not_connected_to_three_hops_route_found_in_case_flag_is_true() {
        let ip_addr = IpAddr::from_str("1.2.3.4").unwrap();
        let initial_node_descriptor = make_node_descriptor_from_ip(ip_addr);
        let mut subject = OverallConnectionStatus::new(vec![initial_node_descriptor]);
        subject.update_can_make_routes(true);

        subject.update_stage_of_overall_connection_status();

        assert_eq!(subject.stage, OverallConnectionStage::ThreeHopsRouteFound);
    }

    #[test]
    fn updates_the_stage_to_three_hops_route_found_in_case_introduction_gossip_is_received_and_flag_is_true(
    ) {
        let ip_addr = IpAddr::from_str("1.2.3.4").unwrap();
        let initial_node_descriptor = make_node_descriptor_from_ip(ip_addr);
        let mut subject = OverallConnectionStatus::new(vec![initial_node_descriptor]);
        let new_ip_addr = IpAddr::from_str("5.6.7.8").unwrap();
        subject.update_connection_stage(ip_addr, ConnectionProgressEvent::TcpConnectionSuccessful);

        subject.update_can_make_routes(true);
        subject.update_connection_stage(
            ip_addr,
            ConnectionProgressEvent::IntroductionGossipReceived(new_ip_addr),
        );

        assert_eq!(subject.stage, OverallConnectionStage::ThreeHopsRouteFound);
    }

    #[test]
    fn updates_the_stage_to_connected_to_neighbor_in_case_standard_gossip_is_received_and_flag_is_false(
    ) {
        let ip_addr = IpAddr::from_str("1.2.3.4").unwrap();
        let initial_node_descriptor = make_node_descriptor_from_ip(ip_addr);
        let mut subject = OverallConnectionStatus::new(vec![initial_node_descriptor]);
        subject.update_connection_stage(ip_addr, ConnectionProgressEvent::TcpConnectionSuccessful);

        subject.update_can_make_routes(false);
        subject.update_connection_stage(ip_addr, ConnectionProgressEvent::StandardGossipReceived);

        assert_eq!(subject.stage, OverallConnectionStage::ConnectedToNeighbor);
    }

    fn make_node_descriptor_from_ip(ip_addr: IpAddr) -> NodeDescriptor {
        NodeDescriptor {
            blockchain: Chain::EthRopsten,
            encryption_public_key: PublicKey::from(vec![0, 0, 0]),
            node_addr_opt: Some(NodeAddr::new(&ip_addr, &vec![1, 2, 3])),
        }
    }
}

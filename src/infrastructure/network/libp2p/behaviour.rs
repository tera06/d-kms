use libp2p::{mdns, request_response, swarm::NetworkBehaviour};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub request_id: String,
    pub timestamp: u64,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignResponse {
    pub request_id: String,
    pub timestamp: u64,
    pub index: Option<usize>,
    pub sign_share: Option<String>,
    pub error: Option<String>,
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "MyBehaviourEvent")]
struct MyBehaviour {
    req_res: request_response::json::Behaviour<SignRequest, SignResponse>,
    mdns: mdns::tokio::Behaviour,
}

enum MyBehaviourEvent {
    ReqRes(request_response::Event<SignRequest, SignResponse>),
    Mdns(mdns::Event),
}

impl From<request_response::Event<SignRequest, SignResponse>> for MyBehaviourEvent {
    fn from(e: request_response::Event<SignRequest, SignResponse>) -> Self {
        MyBehaviourEvent::ReqRes(e)
    }
}

impl From<mdns::Event> for MyBehaviourEvent {
    fn from(e: mdns::Event) -> Self {
        MyBehaviourEvent::Mdns(e)
    }
}

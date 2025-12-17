use std::{
    collections::HashSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use anyhow::anyhow;
use base64::{Engine, engine::general_purpose};
use futures::StreamExt;
use libp2p::{
    StreamProtocol, Swarm, SwarmBuilder, mdns, noise,
    request_response::{self, Message, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use log::info;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use threshold_crypto::{SecretKeyShare, Signature, SignatureShare};
use uuid::Uuid;

use crate::{
    key::{
        decode_signature_secret_key_share, encode_signature_secret_key_share, load_public_key,
        load_secret_key_share,
    },
    types::{SignRequest, SignResponse},
};

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

pub async fn start_server(index: usize) -> Result<()> {
    let mut swarm = create_swarm().await?;
    let secret_key_share = load_secret_key_share(index).await?;

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, multi_addr) in list {
                    swarm
                        .behaviour_mut()
                        .req_res
                        .add_address(&peer_id, multi_addr);
                }
            }

            SwarmEvent::Behaviour(MyBehaviourEvent::ReqRes(request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            })) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if request.timestamp + 300 < now {
                    let resp = SignResponse {
                        request_id: request.request_id.clone(),
                        timestamp: now,
                        index: None,
                        sig_share: None,
                        error: Some("stale request".to_string()),
                    };
                    swarm
                        .behaviour_mut()
                        .req_res
                        .send_response(channel, resp)
                        .ok();
                    continue;
                }

                match handle_sign_request(&request.message, &secret_key_share).await {
                    Ok(signature_secret_key_share) => {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        let resp = SignResponse {
                            request_id: request.request_id.clone(),
                            timestamp: now,
                            index: Some(index),
                            sig_share: Some(signature_secret_key_share),
                            error: None,
                        };

                        _ = swarm.behaviour_mut().req_res.send_response(channel, resp);
                    }
                    Err(e) => {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        let resp = SignResponse {
                            request_id: request.request_id.clone(),
                            timestamp: now,
                            index: None,
                            sig_share: None,
                            error: Some(format!("{}", e)),
                        };
                        _ = swarm.behaviour_mut().req_res.send_response(channel, resp);
                    }
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
            }
            _ => {}
        }
    }
}

pub async fn client_sign(message: &str, threshold: usize) -> Result<()> {
    let mut swarm = create_swarm().await?;

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut discovered_peer_ids = HashSet::new();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    loop {
        tokio::select! {
            event = swarm.select_next_some() =>{
                if let SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) = event{

                    for (peer_id, multi_addr) in list {
                        if !discovered_peer_ids.contains(&peer_id){
                            discovered_peer_ids.insert(peer_id);
                            swarm.behaviour_mut().req_res.add_address(&peer_id, multi_addr);
                        }

                    }

                }

            }

            _ = tokio::time::sleep_until(deadline)=>{
                break;
            }

        }
    }

    if discovered_peer_ids.is_empty() {
        anyhow::bail!("Not found peer")
    }
    info!("discoverd peers");
    let request_id = Uuid::new_v4().to_string();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let req = SignRequest {
        request_id: request_id.clone(),
        timestamp,
        message: general_purpose::STANDARD.encode(message.as_bytes()),
    };

    for peer_id in discovered_peer_ids {
        swarm
            .behaviour_mut()
            .req_res
            .send_request(&peer_id, req.clone());
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);

    let mut shares_map: BTreeMap<usize, SignatureShare> = BTreeMap::new();

    loop {
        tokio::select! {
            event = swarm.select_next_some() =>{
                if let SwarmEvent::Behaviour(MyBehaviourEvent::ReqRes(request_response::Event::Message {  message : Message::Response { response,.. },.. })) = event{
                    if response.request_id != request_id{
                        continue;
                    }
                    if response.error.is_some(){
                        continue;
                    }

                    if let (Some(index), Some(b64_sig_share)) = (response.index, response.sig_share) {
                        match decode_signature_secret_key_share(&b64_sig_share) {
                            Ok(sig_share) =>{
                                shares_map.insert(index, sig_share );
                            }
                            Err(_)=>{
                                continue;
                            }
                        }

                    }



                }
            }
            _ = tokio::time::sleep_until(deadline)=>{
                break;
            }


        }

        if shares_map.len() >= threshold {
            break;
        }
    }

    if shares_map.len() < threshold {
        anyhow::bail!(
            "Not enough signature shares collected: {}/{}",
            shares_map.len(),
            threshold
        );
    }

    let pub_key_set = load_public_key().await?;
    let combined_sig: Signature = pub_key_set
        .combine_signatures(&shares_map)
        .map_err(|e| anyhow!("Failed to combine signatures: {:?}", e))?;

    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let digest = hasher.finalize();

    let pk = pub_key_set.public_key();
    if pk.verify(&combined_sig, &digest) {
        let sig_bytes = bincode::serialize(&combined_sig)?;
        info!("Signature verification succeeded");
        println!("---");
        println!("Message: {}", message);
        println!("Combined signature (hex): {}", hex::encode(&sig_bytes));
        println!("---");
    } else {
        return Err(anyhow!("Combined signature verification failed"));
    }

    Ok(())
}

async fn create_swarm() -> Result<Swarm<MyBehaviour>> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let protocols = vec![(StreamProtocol::new("/d-kms/1.0.0"), ProtocolSupport::Full)];

            let cfg = request_response::Config::default();

            let req_res =
                request_response::json::Behaviour::<SignRequest, SignResponse>::new(protocols, cfg);
            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                    .unwrap();

            MyBehaviour { req_res, mdns }
        })?
        .build();

    Ok(swarm)
}

async fn handle_sign_request(
    b64_message: &str,
    secret_key_share: &SecretKeyShare,
) -> Result<String> {
    let message = general_purpose::STANDARD.decode(b64_message)?;
    let mut hasher = Sha256::new();
    hasher.update(&message);
    let digest = hasher.finalize();

    let signature_share = secret_key_share.sign(&digest);

    let b64_signature_share_bytes = encode_signature_secret_key_share(&signature_share)?;
    Ok(b64_signature_share_bytes)
}

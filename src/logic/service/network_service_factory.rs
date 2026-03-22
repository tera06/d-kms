use crate::logic::service::network_service::NetworkService;

pub trait BuildNetworkSerivce {
    type TError: std::error::Error;
    type TNetworkService: NetworkService;

    fn build(&self) -> Result<Self::TNetworkService, Self::TError>;
}

#[tokio::main]
pub async fn start_server(rendezvous_server:String) {

    crate::RendezvousMediator::start_all(rendezvous_server).await;
}

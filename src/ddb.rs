use mongodb::{
    options::{ClientOptions},
    Client,
    Collection,
};
use actix_web::web;
use mongodb::error::Error;

use crate::user::model::ModelUser;

#[derive(Clone)]
pub struct DDB{
    pub users:Collection<ModelUser>,
}
impl DDB{
    pub async fn new()->Self{
        let client_options = ClientOptions::parse("mongodb+srv://tuanthinhdo37:Concac11@rustdata.uf1ie8u.mongodb.net/?retryWrites=true&w=majority")
        .await
        .expect("Failed to parse options");

        let db_name = "FirstApi";
        // let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
        // client_options.server_api = Some(server_api);

        let client = Client::with_options(client_options).unwrap();

        let db = client.database(db_name);
        let users :Collection<ModelUser>= db.collection("users");
        DDB{users}
    }
}
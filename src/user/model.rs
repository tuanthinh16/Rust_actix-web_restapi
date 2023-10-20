use serde::{Deserialize, Serialize};
use mongodb::bson::{oid::ObjectId, doc, Document};

#[derive(Deserialize,Serialize,Debug,Clone)]
pub struct ModelUser{
    #[serde(default)]
    pub _id: Option<ObjectId>,
    pub email: String,
    pub full_name:String,
    pub password: String,
    pub state :String,
    pub verified : String,
    pub roles : String,
}
#[derive(Deserialize,Serialize,Debug,Clone)]
pub struct UserDTO{
    pub email: String,
    pub password: String,
}
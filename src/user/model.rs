use serde::{Deserialize, Serialize};
use mongodb::bson::{oid::ObjectId, doc, Document};

#[derive(Deserialize,Serialize,Debug,Clone)]
pub struct ModelUser{
    #[serde(default)]
    pub _id: Option<ObjectId>,
    pub username: String,
    pub fullname:String,
    pub password: String,
    pub address : String,
    pub role :String,
    pub phone : String,
    pub last_login : String,
    pub create_time:String,
    pub modify_time : String,

}
#[derive(Deserialize,Serialize,Debug,Clone)]
pub struct UserRDO{
    pub username: String,
    pub password:String,
    pub fullname:String,
    pub address:String,
    pub phone :String,
    pub role : String,
}
#[derive(Deserialize,Serialize,Debug,Clone)]
pub struct UserSDO{
    pub username:String,
    pub password:String,
    pub fullname:String,
}

#[derive(Deserialize,Serialize,Debug,Clone)]
pub struct UserDTO{
    pub username:String,
    pub password:String,
    
}
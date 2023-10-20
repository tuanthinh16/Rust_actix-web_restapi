use std::str::FromStr;

use actix_web::{get, post, put, delete, web, Responder, HttpResponse, ResponseError, http::{header::ContentType, StatusCode}, HttpRequest};
use argon2::{self,Config, Variant, Version, hash_encoded, Error};

use bson::Bson;
use mongodb::{bson::{oid::ObjectId, doc, Document}, options::{FindOneOptions}};
use chrono::{Utc, Duration as ChronoDuration, Local};

use super::model::{ModelUser,UserDTO};
use crate::ddb::DDB;
use futures_util::TryStreamExt;
use derive_more::{Display};
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    email: String,
    exp: usize,
}
#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct TokenData{
    pub email: String,
    pub login_time: chrono::DateTime<Utc>,
    pub exp_time: i64,

}
lazy_static::lazy_static!{
    static ref TOKEN_MAP : Arc<Mutex<HashMap<String,TokenData>>> = Arc::new(Mutex::new(HashMap::new()));
}
#[derive(Debug,Display)]
pub enum UserError{
    UserNotFound,
    UserAlreadyExists,
    UserNotActive,
}
impl ResponseError for UserError{
    fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::build(self.status_code())
        .insert_header(ContentType::json())
        .body(self.to_string())
    }
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            UserError::UserNotFound =>StatusCode::NOT_FOUND,
            UserError::UserAlreadyExists =>StatusCode::ALREADY_REPORTED,
            UserError::UserNotActive =>StatusCode::FAILED_DEPENDENCY,
        }
    }
}

#[post("/user/register/")]
pub async fn insert_user(db_data:web::Data<DDB>, param_obj: web::Json<ModelUser>) -> impl Responder {
    let db = db_data.get_ref();
    let user = ModelUser{
        _id: Some(ObjectId::new()),
        email: param_obj.email.to_string(),
        full_name:param_obj.full_name.to_string(),
        password:hash_password(&param_obj.password.to_string()),
        state:param_obj.state.to_string(),
        verified:param_obj.verified.to_string(),
        roles: param_obj.roles.to_string(),
    };
    let filter = doc! {"email":param_obj.email.to_string()};
    let find_options = FindOneOptions::builder().build();
    match db.users.find_one(filter, find_options).await {
        Ok(rs)=>{
            match rs {
                Some(_)=>{
                    HttpResponse::Conflict().body("User Already Registered")
                }
                None=>{
                    match db.users.insert_one(user.clone(), None).await {
                        Ok(_) => {
                            // If the insertion was successful, return the entire collection of users
                            HttpResponse::Ok().body("Successfully inserted")
                        }
                        Err(e) => {
                            eprintln!("Error inserting user: {:?}", e);
                            HttpResponse::InternalServerError().body("Failed to register user")
                        }
                    }
                }
            }
        }
        Err(e) =>{
            HttpResponse::InternalServerError().body("errror: {:?}")
        }
    }

}

#[post("/login/")]
pub async fn login(db_data:web::Data<DDB>, param_obj: web::Json<UserDTO>) -> impl Responder{
    let db = db_data.get_ref();
    let email = &param_obj.email.to_string();
    let password = &param_obj.password.to_string();
    let filter = doc! {"email": email};
    let options = FindOneOptions::builder().build();
    match db.users.find_one(filter, options).await {
        Ok(rs)=>{
            match rs {
                Some(doc)=>{
                    let pass = doc.password;
                    let is_vaild = verify_password(&pass, password);
                    if is_vaild {
                        let claims = Claims {
                            email: email.clone(),
                            exp: 1000000, // Set your own expiration time 17min
                        };
                        let token = encode(
                            &Header::default(),
                            &claims,
                            &EncodingKey::from_secret("secret".as_ref()), // Set your own secret key
                        );
    
                        match token {
                            Ok(t) => {
                                HttpResponse::Ok().json(t)
                            }
                            Err(_) => HttpResponse::InternalServerError().finish(),
                        }
                    }
                    else{
                        HttpResponse::Unauthorized().body("Password is not correct")
                    }
                }
                None =>{
                    println!("Khong thay!");
                    HttpResponse::NotFound().body("Not Found User")
                }
            }
        }
        Err(e)=>{
            println!("Error: {}", e);
            HttpResponse::NotFound().body("Not Found User")
        }
    }
}
fn login_success(token: &str,data:TokenData)-> impl Responder{
    let login_time = Local::now();
    let utc_time = login_time.with_timezone(&Utc);
    store_token_map(token, TokenData { email: data.email, login_time: (utc_time), exp_time: (data.exp_time) });
    HttpResponse::Ok().body("Save token successfully")
}
fn store_token_map(token: &str,data:TokenData){
    let mut token_map = TOKEN_MAP.lock().unwrap();
    token_map.insert(token.to_string(), data);
}
fn check_token_map(token: &str)-> Option<TokenData>{
    let token_map = TOKEN_MAP.lock().unwrap();
    token_map.get(token).cloned()
}
fn validate_token(req : HttpRequest) ->HttpResponse{
    if let Some(auth_token) = req.headers().get("Authorization"){
        if let Ok(token) = auth_token.to_str(){
            if token.starts_with("Bearer "){
                let token = &token[7..];
                if let Some(data) = check_token_map(token){
                    let current_time = Utc::now().timestamp_millis();
                    //let ex_time = data.login_time + data.exp_time;
                    if data.exp_time >= current_time{
                        return HttpResponse::Ok().body("vaild token");
                    }
                    else{
                        let mut token_map = TOKEN_MAP.lock().unwrap();
                        token_map.remove(token);
                        return HttpResponse::Unauthorized().body("Het han");
                    }
                }
            }
        }
    }
    HttpResponse::Unauthorized().finish()
}
fn hash_password(password: &str) -> String {
    let config = Config {
        variant: Variant::Argon2i,
        version: Version::Version13,
        mem_cost: 65536,
        time_cost: 10,
        lanes: 4,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };

    // Hash password
    let salt = b"somesalt"; // Replace with a random salt for your application
    let hash = argon2::hash_encoded(password.as_bytes(), salt, &config).unwrap();

    hash
}

fn verify_password(hash: &str, password: &str) -> bool {
    match argon2::verify_encoded(hash, password.as_bytes()) {
        Ok(true) => true,
        Ok(false) => false,
        Err(_) => false,
    }
}
// async fn validate_token(req:&HttpRequest) ->Result<HttpResponse,Error>{
//     if let Some(auth_header) = req.headers().get("Authorization") {
//         if let Ok(token) = auth_header.to_str(){
//             if token.starts_with("Bearer "){
//                 let token = &token[7..];
                
//             }
//             if token == "ex"{
//                 return Ok(HttpResponse::Ok().body("dung roi"));
//             }
//         }
//     }
//     Ok(HttpResponse::Unauthorized().finish())
// }
#[post("/user/update/{user_id}")]
pub async fn update_user(data: web::Data<DDB>, path: web::Path<String>,param_obj:web::Json<ModelUser>,req:HttpRequest) -> impl Responder{
    let db = data.as_ref();
    let object_id = ObjectId::from_str(&path).unwrap();
    let filter = doc! {"_id":object_id};
    let options = FindOneOptions::builder().build();
    match db.users.find_one(filter, options).await{
        Ok(rs)=>{
            match rs {
                Some(_)=>{
                    let update_doc = doc! {
                        "$set":{
                            "email":&param_obj.email.to_string(),
                            "password":hash_password(&param_obj.password.to_string()),
                            "full_name":&param_obj.full_name.to_string(),
                            "state":&param_obj.state.to_string(),
                            "verified":&param_obj.verified.to_string(),
                            "roles":&param_obj.roles.to_string(),
                        }
                    };
                    match db.users.update_one(doc! {"_id":object_id}, update_doc, None).await{
                        Ok(_) =>{
                            HttpResponse::Ok().body("Update successfully");
                        }
                        Err(_)=>{
                            HttpResponse::NoContent().body("Failed to update");
                        }
                    }

                }
                None=>{
                    HttpResponse::NoContent().body("Failed to update");
                }
            }
        }
        Err(e)=>{
            println!("An Error: {}", e);
            HttpResponse::NotFound().body("Not Found user");
        }
    }

    HttpResponse::Ok().body("Success")
}

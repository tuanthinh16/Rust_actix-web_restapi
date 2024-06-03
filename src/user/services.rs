use std::str::FromStr;

use actix_web::{cookie::time::Date, delete, get, http::{header::ContentType, StatusCode}, post, put, web, HttpRequest, HttpResponse, Responder, ResponseError};
use argon2::{self,Config, Variant, Version, hash_encoded, Error};


use mongodb::{bson::{oid::ObjectId, doc, Document}, options::{FindOneOptions}};
use chrono::{DateTime, Datelike, Duration as ChronoDuration, Local, NaiveDateTime, Timelike, Utc};
use serde_json::json;

use super::model::{ModelUser,UserDTO,UserRDO,UserSDO};
use crate::ddb::DDB;
use derive_more::{Display};
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};



#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    username: String,
    exp: usize,
}
#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct TokenData{
    pub username: String,
    pub login_time: chrono::DateTime<Local>,
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

#[get("/api/hello")]
pub async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello World !")
}
#[post("/api/register")]
pub async fn insert_user(db_data: web::Data<DDB>, param_obj: web::Json<ModelUser>) -> impl Responder {
    let db = db_data.get_ref();
    let user = ModelUser {
        _id: Some(ObjectId::new()),
        username: param_obj.username.clone(),
        fullname: param_obj.fullname.clone(),
        password: hash_password(&param_obj.password),
        address: param_obj.address.clone(),
        phone: param_obj.phone.clone(),
        role: param_obj.role.clone(),
        create_time: Local::now().to_string(),
        modify_time: Local::now().to_string(),
        last_login: param_obj.last_login.clone(),
    };
    
    
    match db.users.insert_one(user.clone(), None).await {
        Ok(_) => {
            let user_json = serde_json::to_string(&user).unwrap();
            HttpResponse::Ok().content_type("application/json").body(user_json)
        }
        Err(e) => {
            eprintln!("Error inserting user: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to register user")
        }
    }
}

#[post("/api/login")]
pub async fn login(db_data: web::Data<DDB>, param_obj: web::Json<UserDTO>) -> impl Responder {
    let db = db_data.get_ref();
    let username = &param_obj.username.clone();
    let password = &param_obj.password.clone();
    let filter = doc! {"username": username};
    eprintln!("___login. filter {}",filter);
    let options = FindOneOptions::builder().build();
    eprintln!("___login.start get infouser");
    let rs = db.users.find_one(filter, options).await;

    let user_response: Option<UserDTO>; // Khởi tạo một biến tạm thời để lưu trữ dữ liệu

    match rs {
        Ok(result) => {
            if let Some(document) = result {
                user_response = Some(UserDTO {
                    username: document.username.clone(),
                    password: document.password.clone(),
                });
            } else {
                user_response = None;
                eprintln!("Khong tim thay user") // Không tìm thấy tài liệu, gán giá trị None cho user_response
            }
        }
        Err(err) => {
            user_response = None; // Xử lý lỗi, gán giá trị None cho user_response
            eprintln!("Loi :{}",err);
        }
    }

    // Kiểm tra và xử lý dữ liệu được trả về
    if let Some(user) = user_response {
        
        let pass = user.password;
        let is_valid = verify_password(&pass, password);
        if is_valid {
            let claims = Claims {
                username: username.clone(),
                exp: 1000000, // Set your own expiration time 17min
            };
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret("secret".as_ref()), // Set your own secret key
            );

            match token {
                Ok(t) => {
                    let data = TokenData {
                        username: user.username.clone(),
                        login_time: Local::now(),
                        exp_time: 1000000,
                    };
                    login_success(&t, data);
                    let data_json = json!({
                        "username": user.username.clone(),
                        "Token": t,
                        "Exp Time": "1000000 milliseconds",
                        "Login Time": Local::now(),
                    });
                    update_login_time(&db_data,&user.username).await;
                    HttpResponse::Ok().content_type("application/json").body(data_json.to_string())
                }
                Err(_) => HttpResponse::InternalServerError().finish(),
            }
        } else {
            HttpResponse::Unauthorized().body("Password is not correct")
        }
    } else {
        HttpResponse::NoContent().body("User Not Found")
    }
}
fn login_success(token: &str,data:TokenData)-> impl Responder{
    let login_time = Local::now();
    let utc_time = login_time.with_timezone(&Local);
    store_token_map(token, TokenData { username: data.username, login_time: (utc_time), exp_time: (data.exp_time) });
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
fn remove_token(email_user:&str) {
    if let Ok(mut token_map) = TOKEN_MAP.lock(){
        token_map.remove(email_user);
    }
    else{
        eprintln!("Faild remove token");
    }
}
async fn update_login_time(data: &web::Data<DDB>,username:&str){
    let db = data.as_ref();
    let filter = doc! {"username": username};
    let update = doc! {
        "$set": {
            "last_login": Local::now().to_string(),
            
        }
    };
    match db.users.update_one(filter, update, None).await {
        Ok(update_result) => {
            if update_result.matched_count > 0 {
                
                eprintln!("Sucess");
            } else {
                eprintln!("Error when update login time");
            }
        }
        Err(e) => {
            eprintln!("Error updating user: {:?}", e);
            
        }
    }
}
fn validate_token(req : HttpRequest) ->Result<HttpResponse,Error>{
    println!("token: {:?}",req.headers().get("Authorization"));
    if let Some(auth_token) = req.headers().get("Authorization"){
        if let Ok(token) = auth_token.to_str(){
            if token.starts_with("Bearer "){
                let token = &token[7..];
                if let Some(data) = check_token_map(token){
                    let current_time = Utc::now().timestamp_millis();
                    let ex_time = data.login_time.timestamp_millis() + data.exp_time;
                    if ex_time >= current_time{
                        return Ok(HttpResponse::Ok().body("vaild token"));
                    }
                    else{
                        let mut token_map = TOKEN_MAP.lock().unwrap();
                        token_map.remove(token);
                        return Ok(HttpResponse::Unauthorized().body("Het han"));
                    }
                }
            }
        }
    }
    else{
        return Ok(HttpResponse::Unauthorized().finish());
    }
    Ok(HttpResponse::Unauthorized().finish())
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
#[get("/api/user/{user_id}")]
pub async fn get_user(data: web::Data<DDB>, path: web::Path<String>, req: HttpRequest) -> impl Responder {
    let db = data.as_ref();
    let user_id_str = path.into_inner();

    // Chuyển đổi chuỗi user_id sang ObjectId an toàn
    let object_id = match ObjectId::from_str(&user_id_str) {
        Ok(oid) => oid,
        Err(_) => return HttpResponse::BadRequest().body("Invalid ObjectId"),
    };

    let filter = doc! {"_id": object_id};
    let options = FindOneOptions::builder().build();

    match db.users.find_one(filter, options).await {
        Ok(rs) => match rs {
            Some(doc) => {
                let userDoc  = UserRDO{
                    username:doc.username.clone(),
                    fullname:doc.fullname.clone(),
                    password:doc.password.clone(),
                    address : doc.address.clone(),
                    phone:doc.phone.clone(),
                    role:doc.role.clone()
                };
                let user_json = serde_json::to_string(&userDoc).unwrap();
                HttpResponse::Ok().content_type("application/json").body(user_json)
            }
            None => HttpResponse::NotFound().body("Not Found User"),
        },
        Err(_) => HttpResponse::InternalServerError().body("Failed to get user"),
    }
}
#[get("/api/user/username/{username}")]
pub async fn get_user_by_username(data: web::Data<DDB>, path: web::Path<String>, req: HttpRequest) -> impl Responder {
    let db = data.as_ref();
    let user_id_str = path.into_inner();
    let username = user_id_str.to_string();

    let filter = doc! {"username": username};
    let options = FindOneOptions::builder().build();

    match db.users.find_one(filter, options).await {
        Ok(rs) => match rs {
            Some(doc) => {
                let userDoc  = UserRDO{
                    username:doc.username.clone(),
                    fullname:doc.fullname.clone(),
                    password:doc.password.clone(),
                    address : doc.address.clone(),
                    phone:doc.phone.clone(),
                    role:doc.role.clone()
                };
                let user_json = serde_json::to_string(&userDoc).unwrap();
                HttpResponse::Ok().content_type("application/json").body(user_json)
            }
            None => HttpResponse::NotFound().body("Not Found User"),
        },
        Err(e) => 
        {
            eprintln!("Error: {}",e);
            HttpResponse::InternalServerError().body("Failed to get user")
        }
    }
}
#[put("/api/user/{user_id}")]
pub async fn update_user(db_data: web::Data<DDB>, path: web::Path<String>, param_obj: web::Json<ModelUser>) -> impl Responder {
    let db = db_data.get_ref();
    let user_id_str = path.into_inner();

    // Chuyển đổi chuỗi user_id sang ObjectId an toàn
    let object_id = match ObjectId::from_str(&user_id_str) {
        Ok(oid) => oid,
        Err(_) => return HttpResponse::BadRequest().body("Invalid ObjectId"),
    };

    let filter = doc! {"_id": object_id};
    let update = doc! {
        "$set": {
            "username": &param_obj.username,
            "fullname": &param_obj.fullname,
            "password": hash_password(&param_obj.password),
            "address": &param_obj.address,
            "phone": &param_obj.phone,
            "role": &param_obj.role,
            "modify_time": Local::now().to_string(),
            
        }
    };

    match db.users.update_one(filter, update, None).await {
        Ok(update_result) => {
            if update_result.matched_count > 0 {
                let updated_user_json = serde_json::to_string(&param_obj.into_inner()).unwrap();
                HttpResponse::Ok().content_type("application/json").body(updated_user_json)
            } else {
                HttpResponse::NotFound().body("User not found")
            }
        }
        Err(e) => {
            eprintln!("Error updating user: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to update user")
        }
    }
}

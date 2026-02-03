# Chude4 - Thực hành Auth (Identity + JWT) ngắn gọn

## Nội dung
- ASP.NET Core Identity (SQLite)
- JWT token cho API (Bearer)
- Authorization policies (ví dụ: AdminOnly)
- CORS (cho frontend localhost)
- HTTPS redirect

## Chạy dự án
Mở terminal tại `chude4/Chude4.Api` và run project.

Khi chạy lần đầu sẽ tự tạo file database `chude4.db`.

## Cấu hình quan trọng
File: `chude4/Chude4.Api/appsettings.json`
- `Jwt:Key`: đổi sang chuỗi bí mật dài (>= 32 ký tự)
- `Cors:AllowedOrigins`: origin frontend của bạn

## Test nhanh (Swagger hoặc file .http)
### 1) Register
POST `/auth/register`
```json
{ "email": "a@a.com", "password": "123456", "role": "Admin", "age": 18 }
```

### 2) Login lấy token
POST `/auth/login`
```json
{ "email": "a@a.com", "password": "123456" }
```
Response có `accessToken`.

### 3) Gọi API cần đăng nhập
- GET `/me` (chỉ cần đăng nhập)
- GET `/admin` (cần role Admin)

Gắn header:
`Authorization: Bearer <accessToken>`
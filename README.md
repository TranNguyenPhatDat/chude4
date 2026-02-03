# Chude4 - Authentication & Authorization (ASP.NET Core Identity + JWT)

## Tổng quan
Dự án thực hành Web API (.NET 8) với:
- Identity (User/Role/Claims) lưu SQLite
- JWT Bearer (access token)
- Authorization theo Role/Policy (AdminOnly, AtLeast18)
- CORS cho frontend localhost
- Swagger UI hỗ trợ Authorize (Bearer token)

## Công nghệ
- .NET 8 (Minimal API + Controllers)
- ASP.NET Core Identity + EF Core
- SQLite
- JWT (HMAC SHA256)
- Swagger (Swashbuckle)

## Cấu trúc
- `chude4/Chude4.Api/Program.cs`: cấu hình DI, middleware, endpoint
- `chude4/Chude4.Api/appsettings.json`: cấu hình DB, JWT, CORS
- `chude4/Chude4.Api/Chude4.Api.http`: test nhanh bằng REST Client (VS Code)
- `chude4/Chude4.Api/chude4.db`: SQLite database (tự tạo khi chạy lần đầu)

## Quick start
1) Mở terminal tại `chude4/Chude4.Api` và chạy project.
2) Mở Swagger (Development): `https://localhost:<port>/swagger`
3) Register -> Login -> Authorize -> gọi các API protected.

Ghi chú: lần chạy đầu app sẽ tự tạo database `chude4.db`.

## Cấu hình (appsettings.json)
Đường dẫn: `chude4/Chude4.Api/appsettings.json`

### 1) Database
```json
{
  "ConnectionStrings": {
    "Default": "Data Source=chude4.db"
  }
}
```

### 2) JWT
- `Jwt:Key` nên dài >= 32 ký tự.
- Tránh commit key thật khi public repository.

```json
{
  "Jwt": {
    "Issuer": "Chude4",
    "Audience": "Chude4",
    "Key": "CHANGE_ME__VERY_LONG_SECRET_KEY_32+_CHARS",
    "ExpiresMinutes": 60
  }
}
```

### 3) CORS
```json
{
  "Cors": {
    "AllowedOrigins": [
      "http://localhost:5173",
      "https://localhost:5173"
    ]
  }
}
```

## Luồng hoạt động
1) Register: tạo user (tuỳ chọn gán role/age claim)
2) Login: kiểm tra password và trả về `accessToken` (JWT)
3) Gọi API protected: gửi header `Authorization: Bearer <token>`
4) Authorization:
   - `/admin` yêu cầu role `Admin`
   - `/age18` yêu cầu claim `age` và `age >= 18`

## API Endpoints
### A) POST /auth/register
Tạo user mới (có thể gán role và claim `age`).

Request:
```json
{
  "email": "a@a.com",
  "password": "123456",
  "role": "Admin",
  "age": 18
}
```

Response:
- `200 OK`: `{ "message": "Registered" }`
- `400 Bad Request`: lỗi validate/Identity errors

### B) POST /auth/login
Đăng nhập và trả về JWT.

Request:
```json
{
  "email": "a@a.com",
  "password": "123456"
}
```

Response:
- `200 OK`: `{ "accessToken": "<jwt>" }`
- `401 Unauthorized`: sai email/password

### C) GET /me (Requires Auth)
- `200 OK`: token hợp lệ
- `401 Unauthorized`: thiếu/sai token

### D) GET /admin (Requires Admin)
- `200 OK`: có role Admin
- `403 Forbidden`: đã login nhưng không phải Admin

### E) GET /age18 (Requires age >= 18)
- `200 OK`: đủ điều kiện
- `403 Forbidden`: đã login nhưng claim không đạt

## Test bằng Swagger
1) Register -> Login để lấy `accessToken`
2) Nhấn **Authorize** và dán: `Bearer <accessToken>`
3) Gọi `/me`, `/admin`, `/age18`

## Test bằng file .http (VS Code)
Mở file: `chude4/Chude4.Api/Chude4.Api.http`
- Chạy lần lượt: Register -> Login -> `/me` -> `/admin` -> `/age18`

## Ghi chú demo
- Email là duy nhất (RequireUniqueEmail = true). Register trùng email sẽ lỗi.
- Test user thường: register không truyền `role`, login rồi gọi `/admin` sẽ ra 403.
- Test age policy: register age < 18 rồi gọi `/age18` sẽ ra 403.

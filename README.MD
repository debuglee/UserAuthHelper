### 项目说明
    方便用户登录集成


### 安装使用

#### 初始化数据库
```
	dsn := "root:root@tcp(127.0.0.1:8889)/authhelper?charset=utf8mb4&parseTime=True&loc=Local"
	auth_module.InitDB(dsn)
```

#### 在项目中初始化路由与使用

```
    r := mux.NewRouter()
```

#### 需要登录校验的路由
```
	// Import the AuthMiddleware from auth_module
	r.Handle("/protected-endpoint", auth_module.AuthMiddleware(http.HandlerFunc(SomeHandler)))
```


### Demo
```
    package main

    import (
        "UserAuthHelper/auth_module"
        "net/http"

        "github.com/gorilla/mux"
    )

    func main() {
        dsn := "root:root@tcp(127.0.0.1:8889)/authhelper?charset=utf8mb4&parseTime=True&loc=Local"
        auth_module.InitDB(dsn)

        r := mux.NewRouter()

        r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
            auth_module.Login(w, r, auth_module.DB)
        }).Methods("POST")

        r.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
            auth_module.Logout(w, r, auth_module.DB)
        }).Methods("POST")

        r.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
            auth_module.Register(w, r, auth_module.DB)
        }).Methods("POST")

        // Import the AuthMiddleware from auth_module
        r.Handle("/protected-endpoint", auth_module.AuthMiddleware(http.HandlerFunc(SomeHandler)))

        http.ListenAndServe(":8080", r)
    }

    func SomeHandler(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("You have accessed a protected endpoint!"))
    }

```






### MYSQL DB
用户数据库结构
```
CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at DATETIME DEFAULT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    is_active BOOLEAN DEFAULT TRUE
);

```

```
CREATE TABLE whitelisted_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    token TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY (token(255))
);


```
# Battery Management App

A full-stack application for managing battery records with authentication, built using **Next.js (frontend)** and **Go (backend)**

# Link For The Application

The App : https://battery-crud-frontend-5vruvxfy1-ridwan4855s-projects.vercel.app/

If you need the backend as well below is the link :

https://battery-crud-backend-git-main-ridwan4855s-projects.vercel.app/

# Login Application

Username: admin
Password: password

# LogOut Application

- Press F12
- Go to Application
- Search for Local Storage
- You will find key == **authToken**
- delete this token and you will automatically logout

# Installation Frontend for local run

## 1. Clone the Repository

git clone https://github.com/ridwan4855/battery-crud-frontend.git

cd battery-crud-frontend

npm install

## 2. Create env local

Create a **.env.local** file in the root of this folder:

-- NEXT_PUBLIC_API_URL=http://localhost:8080

# Installation BackEnd for local run

## 1. Clone the Repository

git clone https://github.com/ridwan4855/battery-crud-backend.git

cd battery-crud-backend

go mod tidy

go run main.go

## 2. Create env local

Create a **.env.local** file in the root of this folder:

-- JWT_SECRET = **your own secret key**

After the installation of those two Applications you now can run it locally.

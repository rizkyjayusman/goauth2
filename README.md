# Introduction

self-learning project about Oauth2 Client.

# Tech Stack

I used these tech stack for create this project with:
* Go 1.20.2
* [Go default HTTP](https://medium.com/@nate510/don-t-use-go-s-default-http-client-4804cb19f779)
* OAuth2
* Swagger 2

# Architecture

<div align='center'>

![Cooperation Architecture](docs/architecture.png)

</div>

# Api Documentation

This project already have an API Documentation that we create using Swagger 2. 

You can read that documentation on : http://localhost:8000/swagger-ui/

You also can test our API using Postman. You can download the postman file [here](https://github.com/rizkyjayusman/goauth2/blob/main/docs/goauth2.postman_collection.json)


# Implemented Features

This tables shows which features that has been implemented by this repository.

:white_check_mark: : ready

:heavy_exclamation_mark: : in progress

:x: : not yet implemented

| Features                          | Status                              |
| --------------------------------- | ----------------------------------- |
| Login With Github                 |:white_check_mark:                  |
| Unit Test                         | :x:                                 |
| Api Documentation with Swagger    | :x:                  |


# Build and Run

```
1. Clone the Project
   $ git clone git@github.com:rizkyjayusman/goauth2.git
   $ cd goauth2

3. Run the Project
   $ go run .
```
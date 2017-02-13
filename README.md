# A Sample Symfony 2 RESTful API Project with FOSUserBundle + FOSRestBundle + FOSOauthServerBundle for Mobile and Web Clients

This is an example project, ready to use.

## Installation Steps:

**Step 0:**

    Below environment is required:
    Linux
    =====
      - PHP 5.6
      - MySql (though other DB can also be used with a little change in the configuration)
      - Apache2 (alternatively, local PHP dev server can also be used for testing purpose)
      - Composer
      - Chrome browser with Postman plugin or separate Postman installation to test the API (though API can also be  tested via "curl" command)

    Windows
    =======
      - MAMP
      - Composer
      - Chrome browser with Postman plugin or separate Postman installation to test the API (though API can also be  tested via "curl" command)

    Mac
    ===
      - MAMP
      - Composer
      - Chrome browser with Postman plugin or separate Postman installation to test the API (though API can also be  tested via "curl" command)

**Step 1 - Clone the project:**

    Git clone this project from Github to a web folder, say auth, via
    git clone .... auth

    and run
    cd /path/to/auth
    composer install

**Step 2 - Create Database tables**

    cd /path/to/auth
    php app/console doctrine:database:create
    php app/console doctrine:scheme:create

**Step 3 - Create assets**

    cd /path/to/auth
    php app/console assets:install
    php app/console assetic:dump

**Step 4 - Create an Admin user**

    cd /path/to/auth
    php app/console fos:user:create admin admin@example.com password

    Make this user admin

    php app/console fos:user:create admin ROLE_ADMIN

Now you are ready to use the Package!

## Use this Package

1. Test API
2. Use API via a Mobile Client
3. Backend Administration

You will need to start the server before you can use this package:

    cd /path/to/auth
    php app/console server:run

#### 1. Test API

You can test the provided API via curl or Postman. Here we provide as to how to use Postman.

* We have provide sample Postman Collections. Please import any of the Collection to Postman.
* Open the imported Collection and start executing the contained links one by one. For your convenience, we have arranged the links in the preferred order of execution.
* You may start with create the client via API or you will have to use client_id and client_secret of the client created above via command line.


#### 2. Use API via a Mobile Client

Separate sample Github repos are available for iPhone and Android Mobile Clients which use APIs provided by this repo.

    iPhone:
    Android:

#### 3. Backend Administration

In a browser, goto the package site by http://127.0.0.1:8000. This is the Backend Administration tool and can be plugged into any User App easily. It is a simple page. The options are self explanatory.

The salient features of the Backend are:
* The Backend is internationalization enabled. It currently supports English, French and Hindi.
* Options have been provided to pick desired front-end theme for the Backend. The choices available are - Bootstrap, Materialize and Skeleton. **To change the theme, modify key "fronend_theme" in parameters.yml accordingly.** However, the design is open-ended and you may add your preferred theme easily. Please also note that theming has only been provided for base and nav. Other top level stuff is using bootstrap, you can theme as per your choice using base theme.
* The Web user management pages are coming directly from FOSUserBundle views. You may override these pages, per your need.

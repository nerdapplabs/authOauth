# authOauth

### actively maintained at https://github.com/aksinha-nerdapplabs/authOauth

**A Sample Symfony 2 RESTful API Project with FOSUserBundle + FOSRestBundle + FOSOauthServerBundle for Mobile and Web Clients.**

This is an example project, ready to use, based upon **Symfony 2.8** but can be easily adapted to higher Symfony versions. This project is using below Symfony Bundles:

* [FOSUserBundle](https://github.com/FriendsOfSymfony/FOSUserBundle)
* [FOSRestBundle](https://github.com/FriendsOfSymfony/FOSRestBundle)
* [FOSOAuthServerBundle](https://github.com/FriendsOfSymfony/FOSOAuthServerBundle)
* [JMSSerializerBundle](https://github.com/schmittjoh/JMSSerializerBundle)
* [NelmioApiDocBundle](http://symfony.com/doc/current/bundles/NelmioApiDocBundle/index.html)
* [AsseticBundle](https://github.com/symfony/assetic-bundle)

The salient features of this Project are:
* This project consists of **API (currently, user management only) for Frontend consumption, via iPhone and Android Mobiles**, and an **administrative web based Backend system**.
* The APIs and the Backend system are **internationalization enabled**. Project currently supports English, French and Hindi but can be easily extended to include other languages.
* This project implements FOSRestBundle **API versioing system** via custom header **"X-Accept-Version"**. Currently, the running API version is 1.0.
* **Backend theming can easily be customized and extended**. Options have been provided to pick desired front-end theme for the Backend. The choices available are - Bootstrap, Materialize and Skeleton. **To change the theme, modify key "fronend_theme" in parameters.yml accordingly.** However, the design is open-ended and you may add your preferred theme easily. Please also note that theming has only been provided for base and nav. Other top level stuff is using bootstrap, you can theme as per your choice using base theme.
* The Web user management pages are coming directly from FOSUserBundle views. You may override these pages, per your need.

# Table of Contents
* [Requirements](#requirements)
* [Installation](#installation)
* [Configuring Apache2](#configure-apache2)
* [Using the Package](#using-this-package)
* [Roadmap](#roadmap)
* [Change Logs](#change-logs)
* [Contribution Guidelines](#contribution-guidelines)

# <a name="requirements"></a>Requirements

Below environment is required:

* Linux
  - PHP 5.6
  - MySql (though other DB can also be used with a little change in the configuration)
  - Apache2 (alternatively, local PHP dev server can also be used for testing purpose)
  - Composer
  - Chrome browser with Postman plugin or separate Postman installation to test the API (though API can also be  tested via "curl" command)
* Windows
  - MAMP
  - Composer
  - Chrome browser with Postman plugin or separate Postman installation to test the API (though API can also be  tested via "curl" command)
* Mac
  - MAMP
  - Composer
  - Chrome browser with Postman plugin or separate Postman installation to test the API (though API can also be  tested via "curl" command)

***Note regarding Webserver:***

As this project uses OAuth2 server, for smooth results, Apache webserver is highly recommended. You may want to create a site, say http://auth.dev, for it. Please refere to section [Configuring Apache2](#configure-apache2) below for an example implementation.

*However, if you wish to use php local dev server, you will need to start two instances of php local dev server at __two different ports (say 8000 and 8080)__ in two separate terminal windows/tabs,  section [Using the Package](#using-this-package), and replace oauth urls accordingly in Step 2 below. This is necessary as php local dev server is a simple single threaded web server and oAuth server needs to work on more than one process simultaneously. Using a single local dev server severly hampers this and blocks execution.*

# <a name="installation"></a>Installation

**Step 1 - Clone the project:**

    Git clone this project from Github to a web folder, say auth, via
    $ git clone .... auth

    and run
    $ cd /path/to/auth
    $ composer install

**Step 2 - Replace parameter values in parameters.yml**

    database_host: 127.0.0.1
    database_port: 3306
    database_name: authOauth
    database_user: root
    database_password: root
    ...
    ...
    oauth2_auth_endpoint: 'http://auth.dev/oauth/v2/auth'
    oauth2_token_endpoint: 'http://auth.dev/oauth/v2/token'
    frontend_theme: bootstrap

    If you are using php local dev server, assuming you will be using http://127.0.0.1:8000 for browser use, above endpoint will become something like this:

    oauth2_auth_endpoint: 'http://127.0.0.1:8080/oauth/v2/auth'
    oauth2_token_endpoint: 'http://127.0.0.1:8080/oauth/v2/token'

**Step 3 - Create Database tables**

    $ cd /path/to/auth
    $ php app/console doctrine:database:create
    $ php app/console doctrine:schema:create

**Step 4 - Create assets**

    $ cd /path/to/auth
    $ php app/console assets:install
    $ php app/console assetic:dump

**Step 5 - Create an Admin user**

    $ cd /path/to/auth
    $ php app/console fos:user:create admin admin@example.com password

    Make this user admin

    $ php app/console fos:user:promote admin ROLE_ADMIN

Now you are ready to use the Package!

# <a name="configure-apache2"></a>Configuring Apache2

Execute below commands which are specific to Apache2 configuration on Ubuntu 16.04. However, for rest of the env, the detail are quite similar.

```
$ cd /etc/Apache2

$ sudo cp sites-available/000-default.conf sites-available/auth.conf

```

Via an editor, as superuser, copy/paste below section to sites-available/auth.conf:

```
<VirtualHost *:80>
        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        ServerName auth.dev

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html/authOauth/web

        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

Via an editor, as superuser, modify /etc/hosts to include below line:

```
127.0.0.1 auth.dev
```

Now enable auth.conf and restart Apache2:

```
$ sudo a2ensite auth.conf

$ sudo service apache2 restart

$ cd /var/www/html/authOauth

$ sudo setfacl -R -m u:www-data:rX ../authOauth

$ sudo setfacl -R -m u:www-data:rXw app/cache app/logs

$ sudo setfacl -dR -m u:www-data app/cache app/logs

$ sudo chmod -R ogu+rwx app/cache app/logs web
```

# <a name="using-the-package"></a>Use the Package

1. Test API
2. Use API via a Mobile Client
3. Backend Administration

```
Please refer to **Note regarding webserver** in [Requirements](#requirements) section.
If you are using php local dev server, please start the server at two different ports
(say 8000 and 8080) in two terminal windows as below:

In first terminal window,

    cd /path/to/auth
    php app/console server:run 127.0.0.1:8000

In second terminal window,

    cd /path/to/auth
    php app/console server:run 127.0.0.1:8080

You may also need to configure parameters.yml accordingly. Then in a browser, you may use
http://127.0.0.1:8000 to run this package.

Alternatively, if you have successfully configured Apache2, then modify parameters.yml
accordingly can start using the package vide say, http://auth.dev.
```

#### 1. Test API

You can test the provided API via curl or Postman. Here we provide as to how to use Postman.

**API documentation is available, via NelmioApiDocBundle, at http://127.0.0.1:8000/api/doc.**

* We have provide sample Postman Collections. Please import any of the Collection to Postman.
* Open the imported Collection and start executing the contained links one by one. For your convenience, we have arranged the links in the preferred order of execution.
* You may start with create the client via API or you will have to use client_id and client_secret of the client created above via command line.


#### 2. Use API via a Mobile Client

Separate sample Github repos are available for iPhone and Android Mobile Clients which use APIs provided by this repo.

iPhone: https://github.com/ajabble/AJOAuth2

Android: https://github.com/mshariq-nerd/MSOAuth2

#### 3. Backend Administration

In a browser, goto the package site by http://127.0.0.1:8000. This is the Backend Administration tool and can be plugged into any User App easily. It is a simple page. The options are self explanatory.

The salient features of the Backend are:
* The Backend is internationalization enabled. It currently supports English, French and Hindi.
* Options have been provided to pick desired front-end theme for the Backend. The choices available are - Bootstrap, Materialize and Skeleton. **To change the theme, modify key "fronend_theme" in parameters.yml accordingly.** However, the design is open-ended and you may add your preferred theme easily. Please also note that theming has only been provided for base and nav. Other top level stuff is using bootstrap, you can theme as per your choice using base theme.
* The Web user management pages are coming directly from FOSUserBundle views. You may override these pages, per your need.

# <a name="troubleshooting"></a>Troubleshooting

Sometimes, you may run into permission issues. You may try below commands, single or in combination:

```
$ cd /var/www/html/authOauth

$ php app/console cache:clear

$ sudo rm -rf app/cache/* app/logs/*

$ sudo chmod -R ogu+rwx app/cache app/logs web
```

# <a name="roadmap"></a>Roadmap

Here's the TODO list for the next release (**2.0**).

* [ ] Refactoring the UserController to have a single UserController instead of two separate UserControllers for admin and regular user.
* [ ] Refactoring the UserController to use API from AuthController instead using FOSUserBundle so that CRUD comes from a single source.
* [ ] Add provision for admin to reset password for a user.


# <a name="change-logs"></a>Change Logs

# <a name="contribution-guidelines"></a>Contribution Guidelines

Support follows PSR-2 PHP coding standards, and semantic versioning.

Please report any issue you find in the issues page.

## Testing: 
 [How to add test using Crawling](How_to_test_using_Crawling.md)
 
 [Postman Collection with Env, for API Testing](PostmanCollection)


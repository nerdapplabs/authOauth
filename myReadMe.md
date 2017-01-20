
* Clone the repo
* cd {this app folder} // I'm using authOAuth
* Create a db named `authoauth`
* run `composer install`
* run command: `php app/console doctrine:schema:update --force`
* Create a user:

    > We are going to use the command fos:user:create, provided by FOSUserBundle.

    `$ php app/console fos:user:create`
    
    username=aUser
    
    password=test1test1

* create OAuth2 Client:
> We are going to use the command, we registered at `authOauth/src/ApiBundle/Command/CreateClientCommand.php`

    `php app/console aoa:oauth-server:client:create --redirect-uri="http://127.0.0.1:8000/" --grant-type="authorization_code" --grant-typ
e="password" --grant-type="refresh_token" --grant-type="token" --grant-type="client_credentials"`

> On success, you will see:

    `Added a new client with public id 1_22pb5893ejr4sc0og4g0scggogckks8oc0k8scookoowoswwcw, secret l080spsyzbkckckokw84csw000oskck4c80kk88co4owsgg4o`


* Now use postman collection authOauth/authOauth.postman_collection 

    1) getToken is essentially a GET request as:
    
     `http://127.0.0.1:8000/oauth/v2/token?client_id=1_22pb5893ejr4sc0og4g0scggogckks8oc0k8scookoowoswwcw&client_secret=l080spsyzbkckckokw84csw000oskck4c80kk88co4owsgg4o&grant_type=password&username=aUser&password=test1test1`
    
    2) then access users using getUsers. which is 
        
        * GET request
        * Routed to `authOauth/src/ApiBundle/Controller/UsersController.php`

> you may want to see method name, cgetAction, EntityManager vs CreateQueryBuilder, and how to use logs; see config.yml for monolog
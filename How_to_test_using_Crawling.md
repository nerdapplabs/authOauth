#How to do Basic Functional Testing with Symfony 2's Crawler:#

**Step 1: Installing PHPUnit**

Here, I added a (development-time) dependency on phpunit/phpunit to the project's composer.json file:

`composer require --dev phpunit/phpunit`

**Step 2: Creating the Crawling Bundle**

Now we need a bundle to hold our application and test code. Let's create the bundle:

`php app/console generate:bundle --namespace=Crawling/FtestingBundle --format=yml`

Here we specify this bundle's vendor and bundle name, separated by a forward slash (/). Lastly, we tell it to use YAML as the format for our configuration. Now you can use whatever format you'd like if you don't want to use YAML and you could also name your bundle however you prefer, just as long as you first give it a vendor name and end your bundle name with the suffix Bundle. For example: FtestingBundle.

**Step 3: How To Run Tests**

To run test from project root, run PHPUnit: 
`$ vendor/phpunit/phpunit/phpunit -c app/`
    
It will run all the tests in the project. And then you should see the coveted green bar. Green means success of test and Red means failure.

If you want to run any specific test, then run:
`$ vendor/phpunit/phpunit/phpunit -c app/ path/to/your/test`
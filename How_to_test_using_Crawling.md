#How to do Basic Functional Testing with Symfony 2's Crawler:#
Symfony 2 offers a complete integration testing suite that you can use to make sure your applications run 
just as you expect. Here is, How we can use Symfony 2 and PHPUnit, the testing framework that it employs, 
to write basic functional tests using the Crawler:

**Step 1:**

    Create a new project using the Symfony 2.

**Step 2: Installing PHPUnit**

    Simply add a (development-time) dependency on phpunit/phpunit to your project's composer.json file if 
    you use Composer to manage the dependencies of your project:
	    composer require --dev phpunit/phpunit

**Step 3: Creating the Crawling Bundle**

    Now we need a bundle to hold our application and test code. Let's create:
        php app/console generate:bundle --namespace=Crawling/FtestingBundle --format=yml

    Here we specify this bundle's Vendor and bundle name, separated by a forward slash (/). Lastly, we tell 
    it to use YAML as the format for our configuration. Now you can use whatever format you'd like if you don't 
    want to use YAML and you could also name your bundle however you prefer, just as long as you first give it a 
    vendor name and end your bundle name with the suffix Bundle.

**Step 4: How To Run Tests**

    From project root, run PHPUnit: 
        $ vendor/phpunit/phpunit/phpunit -c app/
    
    It will run all the tests in the project. And then you should see the coveted green bar. Green means 
    success of test and Red means failure.

    If you want to run any specific test, then run:
        $ vendor/phpunit/phpunit/phpunit -c app/ path/to/your/test


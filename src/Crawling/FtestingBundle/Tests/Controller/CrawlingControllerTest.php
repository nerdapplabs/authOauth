<?php
 
namespace Crawling\FtestingBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
 
class CrawlingControllerTest extends WebTestCase {
    public function testHome() {
     $client = static::createClient();
     $crawler = $client->request('GET', '/crawling/home');
     $heading = $crawler->filter('h1')->eq(0)->text();
     $this->assertEquals('Crawling Home Page', $heading);
    } 
}
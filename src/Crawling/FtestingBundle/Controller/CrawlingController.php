<?php
 
namespace Crawling\FtestingBundle\Controller;
 
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
 
class CrawlingController extends Controller {
    public function homeAction() {
        return $this->render('CrawlingFtestingBundle:Crawling:home.html.twig');
    }
 
    public function otherAction() {
        return $this->render('CrawlingFtestingBundle:Crawling:other.html.twig');
    }
}
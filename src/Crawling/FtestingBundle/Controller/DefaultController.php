<?php

namespace Crawling\FtestingBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class DefaultController extends Controller
{
    public function indexAction()
    {
        return $this->render('CrawlingFtestingBundle:Default:index.html.twig');
    }
}

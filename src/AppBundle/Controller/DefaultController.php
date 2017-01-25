<?php

namespace AppBundle\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

class DefaultController extends Controller
{
    /**
     * @Route("/", name="homepage")
     */
    public function indexAction(Request $request)
    {
      $theme = $this->container->getParameter('frontend_theme');
      $base_dir = realpath($this->container->getParameter('kernel.root_dir').'/..').DIRECTORY_SEPARATOR;

      $dir    = $base_dir.'/web/'.$theme.'/css';
      $cssFiles = scandir($dir);
      $dir    = $base_dir.'/web/'.$theme.'/js';
      $jsFiles = scandir($dir);

        // replace this example code with whatever you need
        return $this->render('default/index.html.twig', array(
            'base_dir' => $base_dir, 'theme' => $theme, 'cssFiles' => $cssFiles, 'jsFiles' => $jsFiles
        ));
    }
}

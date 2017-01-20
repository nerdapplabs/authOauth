<?php

namespace ApiBundle\Controller;

use ApiBundle\Entity\User;
use ApiBundle\Form\UserType;
use Symfony\Component\HttpFoundation\Request;
use FOS\RestBundle\Controller\FOSRestController;
use FOS\RestBundle\Routing\ClassResourceInterface;
use Symfony\Component\HttpFoundation\File\Exception\AccessDeniedException;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;


class UsersController extends FOSRestController implements ClassResourceInterface
{
    /**
     * @Route("/users", name="users")
     */
    public function cgetAction()
    {
        //security.yml is configured to allow anonymous access to controllers
        //checking for authorization in each controller allows more flexibility
        //to change this remove anonymous: true in security.yml on firewall
        if (!$this->get('security.authorization_checker')->isGranted('IS_AUTHENTICATED_FULLY')) {
            throw $this->createAccessDeniedException();
        }

        /*$em = $this->getDoctrine()->getEntityManager();
        $repository = $em->getRepository("ApiBundle:User");
        $users = $repository->findAll();
        */ 

        $repository = $this->getDoctrine()->getRepository("ApiBundle:User");

    // createQueryBuilder() automatically selects FROM ApiBundle:User
    // and aliases it to "u"
        $query = $repository->createQueryBuilder('u')->select('u.username', 'u.email')->getQuery();

        $users = $query->getResult();

        $logger = $this->get('logger');
       // $logger->info('I just got the logger');
       // $logger->error('An error occurred');

       $logger->critical('Users fetched', $users);

        $view = $this->view($users, 200)
            ->setTemplate("default/users.html.twig")
            ->setTemplateVar('users')
        ;


        return $this->handleView($view);
    }
   
}

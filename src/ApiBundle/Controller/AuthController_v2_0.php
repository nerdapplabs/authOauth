<?php

// Use statements are not inherited. So the need for below all lines.
// See http://stackoverflow.com/questions/11794901/php-does-extending-class-need-another-use-to-call-namespace
// Also http://php.net/manual/en/language.namespaces.importing.php

namespace ApiBundle\Controller;

use ApiBundle\Entity\User;
use ApiBundle\Form\UserType;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use FOS\RestBundle\Controller\Annotations\RouteResource;
use Symfony\Component\HttpFoundation\JsonResponse;

use Symfony\Component\HttpFoundation\File\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AccessDeniedException as SecurityCoreExceptionAccessDeniedException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\Security\Core\Exception\AccountStatusException;

use FOS\RestBundle\Controller\FOSRestController;
use FOS\RestBundle\Routing\ClassResourceInterface;
use FOS\UserBundle\Model\UserInterface;
use Nelmio\ApiDocBundle\Annotation\ApiDoc;

use Symfony\Component\DependencyInjection\ContainerAware;
use Symfony\Component\Security\Core\SecurityContext;

use OAuth2;

use FOS\RestBundle\Controller\Annotations\Version;
use FOS\RestBundle\Controller\Annotations\NamePrefix;
use FOS\RestBundle\Controller\Annotations\Prefix;
use FOS\RestBundle\Controller\Annotations\Get;
use FOS\RestBundle\Controller\Annotations\Post;

/**
  * @Version({"2.0"})
  *
  * @NamePrefix("api_v2_0_")
  * @Prefix("/api")
  * @RouteResource("User")
  */
class AuthController_v2_0 extends \ApiBundle\Controller\AuthController
{
    /**
      * @Get("/user/dummy")
      */
    public function getDummyAction()
    {
        return new JsonResponse(array(
          'show_message' => 'This is from v2.0',
        ));
    }
}

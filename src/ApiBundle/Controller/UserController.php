<?php

namespace ApiBundle\Controller;

use ApiBundle\Entity\User;
use ApiBundle\Form\UserType;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use FOS\RestBundle\Controller\Annotations\RouteResource;

use Symfony\Component\HttpFoundation\File\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AccessDeniedException as SecurityCoreExceptionAccessDeniedException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Exception\AccountStatusException;

use FOS\RestBundle\Controller\FOSRestController;
use FOS\RestBundle\Routing\ClassResourceInterface;
use FOS\UserBundle\Model\UserInterface;

use Symfony\Component\DependencyInjection\ContainerAware;
use Symfony\Component\Security\Core\SecurityContext;
use Symfony\Component\HttpFoundation\JsonResponse;
use OAuth2;
use Nelmio\ApiDocBundle\Annotation\ApiDoc;


class UserController extends FOSRestController implements ClassResourceInterface
{
    const SESSION_EMAIL = 'fos_user_send_resetting_email/email';

    /**
      * Fetch all Users.
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Fetch All Users",
      * )
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

    /**
      * Register a new user. Will return a JsonResponse(username, msg, oAuthRtn, code) upon success, else
      * will throw ErrorException in html.
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Register a new user",
      *  parameters={
      *      {"name"="client_id", "dataType"="string", "required"=true, "description"="oAuth ClientId"},
      *      {"name"="client_secret", "dataType"="string", "required"=true, "description"="oAuth ClientSecret"},
      *      {"name"="username", "dataType"="string", "required"=true, "description"="username"},
      *      {"name"="password", "dataType"="string", "required"=true, "description"="password"},
      *      {"name"="firstname", "dataType"="string", "required"=true, "description"="firstname"},
      *      {"name"="lastname", "dataType"="string", "required"=true, "description"="lastname"},
      *      {"name"="dob", "dataType"="datetime", "required"=true, "description"="date of birth"},
      *      {"name"="email", "dataType"="email", "required"=true, "description"="Email"},
      *      {"name"="email_confirmation", "dataType"="integer", "required"=true, "description"="0-email confirmation not required, 1-required"}
      *  },
      * )
      */
    public function getRegisterAction()
    {
        $userManager = $this->get('fos_user.user_manager');
        $entityManager = $this->get('doctrine')->getManager();
        $request = $this->container->get('request');

        $method = $this->get('request')->getMethod();
        if ('GET' === $method) {
          $data = $request->query->all();
        } else {
          $data = $request->request->all();
        }
        $username = $data['username'];
        $password = $data['password'];
        $email = $data['email'];
        $confirmationEnabled = $data['email_confirmation'];

        $firstname = $data['firstname'];
        $lastname = $data['lastname'];
        $dob = $data['dob'];

        // Do a check for existing user with userManager->findByUsername
        /** @var $user UserInterface */
        $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($username);

        if (null != $user) {
            return new JsonResponse(array('invalid_username' => $username));
        }

        $user = $userManager->createUser();

        $user->setUsername($username);
        $user->setPlainPassword($password);
        $user->setEmail($email);
        $user->setFirstname($firstname);
        $user->setLastname($lastname);
        $user->setDob($dob);
        $user->setRoles(array('ROLE_USER', 'ROLE_API'));
        $user->setEnabled(true);

        $userManager->updateUser($user);

        $accessToken = 'Pending';
        $msg = 'N.A.';

        if ('1' == $confirmationEnabled) {
            $msg = 'Please check your email to complete the registration.';
        } else {
            $msg = 'Registration complete. Welcome!';
            $clientId = $data['client_id'];
            $clientSecret = $data['client_secret'];
            $oAuthRtn = $this->fetchAccessToken($clientId, $clientSecret, $username, $password);
        }

        return new JsonResponse(array(
                'username' => $username,
                'msg' => $msg,
                'access_token' => $oAuthRtn,
                'code' => 201
        ));
    }

    /**
      * Change Password request. Will return a JsonResponse(username, msg) upon success, else
      * will throw ErrorException in html. Since existing user is verified by access_token,
      * username + old password is not needed.
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Change password of the user",
      *  parameters={
      *      {"name"="access_token", "dataType"="string", "required"=true, "description"="oAuth Access Token"},
      *      {"name"="password", "dataType"="string", "required"=true, "description"="New password"},
      *  },
      * )
      */
    public function getChangePasswordAction()
    {
        $user = $this->container->get('security.context')->getToken()->getUser();
        if (!is_object($user) || !$user instanceof UserInterface) {
            throw new AccessDeniedException('invalid User or this user does not have access to this section.');
        }

        $userManager = $this->get('fos_user.user_manager');
        $entityManager = $this->get('doctrine')->getManager();
        $request = $this->container->get('request');

        $method = $this->get('request')->getMethod();
        if ('GET' === $method) {
          $data = $request->query->all();
        } else {
          $data = $request->request->all();
        }
        $password = $data['password'];

        $user->setPlainPassword($password);
        $msg = 'Password changed successfully';

        $userManager->updateUser($user);

        return new JsonResponse(array(
                'username' => $user->getUsername(),
                'msg' => $msg
        ));
    }

    /**
      * Fetch User profile detail. Will return a JsonResponse(username...) upon success, else
      * will throw ErrorException in html. Since existing user is verified by access_token,
      * username + old password is not needed.
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Fetch User profile detail",
      *  parameters={
      *      {"name"="access_token", "dataType"="string", "required"=true, "description"="oAuth Access Token"},
      *  },
      * )
      */
    public function getProfileShowAction()
    {
        $user = $this->container->get('security.context')->getToken()->getUser();
        if (!is_object($user) || !$user instanceof UserInterface) {
            throw new AccessDeniedException('This user does not have access to this section.');
        }

        return new JsonResponse(array(
          'username' => $user->getUsername(),
          'firstname' => $user->getFirstname(),
          'lastname' => $user->getLastname(),
          'dob' => $user->getDob(),
          'email' => $user->getEmail()
        ));
    }

    /**
      * Update User profile detail. Will return a JsonResponse(username, msg) upon success, else
      * will throw ErrorException in html. Since existing user is verified by access_token,
      * username + old password is not needed.
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Update User profile detail",
      *  parameters={
      *      {"name"="access_token", "dataType"="string", "required"=true, "description"="oAuth Access Token"},
      *      {"name"="name", "dataType"="string", "required"=true, "description"="User Cannonical name"},
      *  },
      * )
      */
    public function getProfileEditAction()
    {
        $user = $this->container->get('security.context')->getToken()->getUser();
        if (!is_object($user) || !$user instanceof UserInterface) {
            throw new AccessDeniedException('This user does not have access to this section.');
        }

        $userManager = $this->get('fos_user.user_manager');
        $entityManager = $this->get('doctrine')->getManager();
        $request = $this->container->get('request');

        $method = $this->get('request')->getMethod();
        if ('GET' === $method) {
          $data = $request->query->all();
        } else {
          $data = $request->request->all();
        }

        $username = $data['username'];
        $firstname = $data['firstname'];
        $lastname = $data['lastname'];
        $email = $data['email'];
        $dob = $data['dob'];

        if ($username) {
          $user->setUsername($username);
        }
        if ($firstname) {
          $user->setFirstname($firstname);
        }
        if ($lastname) {
          $user->setLastname($lastname);
        }
        if ($dob) {
          $user->setDob($dob);
        }
        if ($email) {
          $user->setEmail($email);
        }

        $userManager->updateUser($user);

        $msg = 'Profile changed successfully';

        $username = $user->getUsername();

        return new JsonResponse(array(
                'username' => $username,
                'msg' => $msg
        ));
    }

    /**
      * Request reset user password. A mail will be sent, if not sent earlier else will return  error msg.
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Request reset user password: submit form and send email",
      *  parameters={
      *      {"name"="username", "dataType"="string", "required"=true, "description"="username"},
      *  },
      * )
      */
    public function getResettingRequestEmailAction()
    {
        $username = $this->container->get('request')->request->get('username');

        /** @var $user UserInterface */
        $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($username);

        if (null === $user) {
            throw new AccessDeniedException('This user does not have access to this section.');
        }

        if ($user->isPasswordRequestNonExpired($this->container->getParameter('fos_user.resetting.token_ttl'))) {
            return new JsonResponse(array('msg' => 'Password reset request already received'));
        }

        if (null === $user->getConfirmationToken()) {
            /** @var $tokenGenerator \FOS\UserBundle\Util\TokenGeneratorInterface */
            $tokenGenerator = $this->container->get('fos_user.util.token_generator');
            $user->setConfirmationToken($tokenGenerator->generateToken());
        }

        $this->container->get('session')->set(static::SESSION_EMAIL, $this->getObfuscatedEmail($user));
        $this->container->get('fos_user.mailer')->sendResettingEmailMessage($user);
        $user->setPasswordRequestedAt(new \DateTime());
        $this->container->get('fos_user.user_manager')->updateUser($user);

        return new RedirectResponse($this->container->get('router')->generate('api_get_user_resetting_check_email'));
    }

    /**
      * Tell the user to check his email provider
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Tell the user to check his email provider",
      *  parameters={
      *      {"name"="access_token", "dataType"="string", "required"=true, "description"="oAuth Access Token"},
      *  },
      * )
      */
    public function getResettingCheckEmailAction()
    {
        $session = $this->container->get('session');
        $email = $session->get(static::SESSION_EMAIL);
        $session->remove(static::SESSION_EMAIL);

        if (empty($email)) {
            // the user does not come from the sendEmail action
            return new RedirectResponse($this->container->get('router')->generate('api_get_user_resetting_request_email'));
        }

        return new JsonResponse(array('msg' => 'Mail already send to '.$email.'. Please check your mail.'));
    }

    /**
     * Get the truncated email displayed when requesting the resetting.
     *
     * The default implementation only keeps the part following @ in the address.
     *
     * @param \FOS\UserBundle\Model\UserInterface $user
     *
     * @return string
     */
    protected function getObfuscatedEmail(UserInterface $user)
    {
        $email = $user->getEmail();
        if (false !== $pos = strpos($email, '@')) {
            $email = '...' . substr($email, $pos);
        }

        return $email;
    }

    /**
      * Get Access Token. Will return a JsonResponse from oAuth upon success, else
      * will throw ErrorException in html.
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Request an oAuth Access Token",
      *  parameters={
      *      {"name"="client_id", "dataType"="string", "required"=true, "description"="oAuth ClientId"},
      *      {"name"="client_secret", "dataType"="string", "required"=true, "description"="oAuth ClientSecret"},
      *      {"name"="username", "dataType"="string", "required"=true, "description"="username"},
      *      {"name"="password", "dataType"="string", "required"=true, "description"="password"},
      *  },
      * )
      */
    public function getAccessTokenAction()
    {
        $userManager = $this->get('fos_user.user_manager');
        $entityManager = $this->get('doctrine')->getManager();
        $request = $this->container->get('request');

        $method = $this->get('request')->getMethod();
        if ('GET' === $method) {
          $data = $request->query->all();
        } else {
          $data = $request->request->all();
        }

        $username = $data['username'];
        $password = $data['password'];
        $clientId = $data['client_id'];
        $clientSecret = $data['client_secret'];

        if (!$username || !$password || !$clientId || !$clientSecret) {
            throw new AccessDeniedException('Unable to obtain Access Token for missing username/password/clientId/clientSecret.');
        }

        return new JsonResponse($this->fetchAccessToken($clientId, $clientSecret, $username, $password));
    }

    /**
      * Fetch oAuth Access Token from oAuth engine.
      *
      */
    private function fetchAccessToken($clientId, $clientSecret, $username, $password)
    {
        $client = new OAuth2\Client($clientId, $clientSecret);
        $params = array('username' => $username,
                        'password' => $password);

        $response = $client->getAccessToken($this->container->getParameter('oauth2_token_endpoint'),
                                            'password', $params);

        $accessToken = 'Total Garbage';
        if(isset($response['result']) && isset($response['result']['access_token'])) {
            $accessToken = $response['result']['access_token'];
            // $this->client->setAccessToken($accessToken);
        }

        return $response['result'];
    }
}

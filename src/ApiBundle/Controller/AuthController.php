<?php

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
 * @Version({"1.0"})
 *
 * @NamePrefix("api_v1_0_")
 * @Prefix("/api")
 * @RouteResource("User")
 */
class AuthController extends FOSRestController implements ClassResourceInterface
{
    const SESSION_EMAIL = 'fos_user_send_resetting_email/email';

    /**
      * @Get("/user/dummy")
      */
    public function getDummyAction()
    {
        return new JsonResponse(array(
          'show_message' => 'This is from v1.0',
        ));
    }

    /**
      * Fetch all Users.
      *
      * @Get("/users")
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Fetch All Users",
      * )
      *
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

      $this->logMessage(200, 'Users fetched '.serialize($users));

      $view = $this->view($users, 200)
          ->setTemplate("default/users.html.twig")
          ->setTemplateVar('users')
      ;

      return $this->handleView($view);
    }

    /**
      * Create a new Client for the given URL. Only to be created by Admin.
      *
      * @Post("/user/new/client")
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Create a new Client",
      *  parameters={
      *      {"name"="username", "dataType"="string", "required"=true, "description"="Admin username"},
      *      {"name"="password", "dataType"="string", "required"=true, "description"="password"},
      *      {"name"="name", "dataType"="string", "required"=true, "description"="Client name"},
      *      {"name"="redirect_url", "dataType"="string", "required"=true, "description"="Redirect URL"},
      *      {"name"="_locale", "dataType"="string", "required"=false, "description"="User locale. Will default to en"}
      *  },
      * )
      */
    public function newClientAction()
    {

        $request = $this->container->get('request');

        $this->validateAdminUser($request);
        $this->validateClientName($request);
        $this->validateUrl($request);

        // Everything ok, now proceed to create the client
        $clientManager = $this->container->get('fos_oauth_server.client_manager.default');
        $client = $clientManager->createClient();
        $client->setName($request->request->get('name'));
        $client->setRedirectUris(array($request->request->get('redirect_url')));
        $client->setAllowedGrantTypes(array("authorization_code",
                                            "password",
                                            "refresh_token",
                                            "token",
                                            "client_credentials"
                                      ));

        $clientManager->updateClient($client);

        $this->logMessage(200, 'Client successfully created: '.$client->getPublicId());

        return new JsonResponse(array(
          'code' => 200,
          'show_message' => 'Client successfully created.',
          'client_id' => $client->getPublicId(),
          'client_secret' => $client->getSecret()
        ));
    }

    /**
      * Validate Client name
      */
    private function validateClientName(Request $request) {
      $clientName = $request->request->get('name');

      // Check Client name is not empty
      if (!$clientName) {
          $this->logAndThrowError(400, 'Client Name cannot be empty', $this->get('translator')->trans('api.show_error_client_name', array(), 'messages', $request->getLocale()), $request->getLocale());
      }
    }

    /**
      * Validate Redirect URL
      */
    private function validateUrl(Request $request) {
      $redirectUrl = $request->request->get('redirect_url');

      // Check Redirect URL is not empty
      if (!$redirectUrl) {
          $this->logAndThrowError(400, 'Redirect URL cannot be empty', $this->get('translator')->trans('api.show_error_url', array(), 'messages', $request->getLocale()), $request->getLocale());
      }
    }

    /**
      * Validate Admin User
      */
    private function validateAdminUser(Request $request) {
      $username = $request->request->get('username');
      $password = $request->request->get('password');

      $entityManager = $this->get('doctrine')->getManager();
      $query = $entityManager->createQuery("SELECT u FROM \ApiBundle\Entity\User u WHERE u.username = :username");
      $query->setParameter('username', $username);
      $user = $query->getOneOrNullResult();

      // Check for the valid Admin user
      if ($user) {
        // Get the encoder for the users password
        $encoder_service = $this->get('security.encoder_factory');
        $encoder = $encoder_service->getEncoder($user);

        if ($encoder->isPasswordValid($user->getPassword(), $password, $user->getSalt())) {
          // Not an Admin
          if (!in_array('ROLE_ADMIN', $user->getRoles())) {
            $this->logAndThrowError(400, 'User '.$username.' is not an Admin. Role(s) assigned: '.implode($user->getRoles(), ', '), $this->get('translator')->trans('api.show_error_non_admin', array(), 'messages', $request->getLocale()), $request->getLocale());
          }
        } else {
            // Password bad
            $this->logAndThrowError(400, 'Password does not match: '. $password, $this->get('translator')->trans('api.show_error_password', array(), 'messages', $request->getLocale()), $request->getLocale());
        }
      } else {
        // Username bad
        $this->logAndThrowError(400, 'Invalid username: '.$username, $this->get('translator')->trans('api.show_error_username_missing', array(), 'messages', $request->getLocale()), $request->getLocale());
      }
    }

    /**
      * Register a new user. Will return a JsonResponse(username, msg, oAuthRtn, code) upon success.
      *
      *
      * @Post("/user/register")
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
      *      {"name"="dob", "dataType"="datetime", "required"=true, "description"="date of birth mm/dd/yyyy"},
      *      {"name"="email", "dataType"="email", "required"=true, "description"="Email"},
      *      {"name"="email_confirmation", "dataType"="integer", "required"=true, "description"="0-email confirmation not required, 1-required"},
      *      {"name"="scope", "dataType"="string", "required"=true, "description"="Fixed value - API"},
      *      {"name"="_locale", "dataType"="string", "required"=false, "description"="User locale. Will default to en"}
      *  },
      * )
      */
    public function postRegisterAction()
    {
        $request = $this->container->get('request');
        $userManager = $this->get('fos_user.user_manager');

        $this->validateClient($request);
        $this->validateUsername($request);
        $this->validatePassword($request);
        $this->validateEmail($request);
        $this->validateFirstname($request);
        $this->validateDob($request);
        $this->validateScope($request);

        $user = $userManager->createUser();

        $user->setUsername($request->request->get('username'));
        $user->setPlainPassword($request->request->get('password'));
        $user->setEmail($request->request->get('email'));
        $user->setFirstname($request->request->get('firstname'));
        $user->setLastname($request->request->get('lastname'));
        $user->setDob($request->request->get('dob'));
        $user->setRoles(array('ROLE_'. $request->request->get('scope')));
        $user->setEnabled(true);

        $userManager->updateUser($user);

        $oAuthRtn = 'Pending';
        $msg = 'N.A.';
        $grantType = 'password';

        if ('1' == $request->request->get('email_confirmation')) {
            $msg = 'Please check your email to complete the registration.';
        } else {
            $msg = 'Registration complete. Welcome!';
            $oAuthRtn = $this->fetchAccessToken($request, $grantType);
        }

        $this->logMessage(201, 'User successfully created '.$request->request->get('username') );

        return new JsonResponse(array(
                'code' => 201,
                'show_message' => $msg,
                'username' => $request->request->get('username'),
                'oauth' => $oAuthRtn
        ));
    }

    /**
      * Validate Client Credentials
      */
    private function validateClient(Request $request) {
      $clientId = $request->request->get('client_id');
      $clientSecret = $request->request->get('client_secret');

      // First check for valid Client Credentials
      $pos = strpos($clientId, '_');
      $id = substr($clientId, 0, $pos);
      $randomId = substr($clientId, $pos + 1);

      $clientManager = $this->container->get('fos_oauth_server.client_manager.default');
      $client = $clientManager->findClientBy(array(
          'id'       => $id,
          'randomId' => $randomId,
          'secret'   => $clientSecret
      ));

      if (null == $client) {
          $this->logAndThrowError(400, 'Invalid Client Credentials: '.$clientId);
      }
    }

    /**
      * Validate username
      */
    private function validateUsername(Request $request) {
      $username = $request->request->get('username');

      // Check if username is empty
      if (null == $username) {
          $this->logAndThrowError(400, 'Empty username', $this->get('translator')->trans('api.show_error_username_missing', array(), 'messages', $request->getLocale()), $request->getLocale());
      }

      // Do a check for existing user with userManager->findByUsername
      /** @var $user UserInterface */
      $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($username);
      if (null != $user) {
        $this->logAndThrowError(400, 'User already exists. Username: '.$user->getUsername(), $this->get('translator')->trans('api.show_error_username_taken', array(), 'messages', $request->getLocale()), $request->getLocale());
      }
    }

    /**
      * Validate password
      */
    private function validatePassword(Request $request) {
      $password = $request->request->get('password');

      // Check if password is empty
      if (null == $password) {
          $this->logAndThrowError(400, 'Invalid empty password', $this->get('translator')->trans('api.show_error_password', array(), 'messages', $request->getLocale()), $request->getLocale());
      }
    }

    /**
      * Validate email
      */
    private function validateEmail(Request $request) {
      $email = $request->request->get('email');

      // Check if email is valid
      if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $this->logAndThrowError(400, 'Invalid email: '.$email, $this->get('translator')->trans('api.show_error_email', array(), 'messages', $request->getLocale()), $request->getLocale());
      }

      $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($email);
      if (null != $user) {
        $this->logAndThrowError(400, 'Email '.$user->getEmail().' already taken by Username: '.$user->getUsername(), $this->get('translator')->trans('api.show_error_email_taken', array(), 'messages', $request->getLocale()), $request->getLocale());
      }
    }

    /**
      * Validate firstname
      */
    private function validateFirstname(Request $request) {
      $firstname = $request->request->get('firstname');

      // Check if firstname is empty. At least firstname is required.
      if (null == $firstname) {
          $this->logAndThrowError(400, 'Invalid empty firstname', $this->get('translator')->trans('api.show_error_firstname', array(), 'messages', $request->getLocale()), $request->getLocale());
      }

    }

    /**
      * Validate dob
      */
    private function validateDob(Request $request) {
      $dob = $request->request->get('dob');

      // Check if dob is valid
      list($mm,$dd,$yyyy) = explode('/',$dob);
      if (!checkdate($mm,$dd,$yyyy)) {
          $this->logAndThrowError(400, 'Invalid mm/dd/yyyy DOB: '.$dob, $this->get('translator')->trans('api.show_error_dob', array(), 'messages', $request->getLocale()), $request->getLocale());
      }
    }

    /**
      * Validate dob
      */
    private function validateScope(Request $request) {
      $scope = $request->request->get('scope');

      // Check if scope is set to API
      if ('API' != $scope) {
          $this->logAndThrowError(400, 'Invalid scope: '.$scope, $this->get('translator')->trans('api.show_error_scope', array(), 'messages', $request->getLocale()), $request->getLocale());
      }
    }

    /**
      * Change Password request. Will return a JsonResponse(username, msg) upon success.
      *
      *
      * @Post("/user/profile/change-password")
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Change password of the user. Access token to be provided in header (Authorization = Bearer <access token>)",
      *  parameters={
      *      {"name"="old_password", "dataType"="string", "required"=true, "description"="Old password"},
      *      {"name"="password", "dataType"="string", "required"=true, "description"="New password"},
      *      {"name"="_locale", "dataType"="string", "required"=false, "description"="User locale. Will default to en"}
      *  },
      * )
      */
    public function editPasswordAction()
    {
        $request = $this->container->get('request');

        $user = $this->container->get('security.context')->getToken()->getUser();
        if (!is_object($user) || !$user instanceof UserInterface) {
            $this->logAndThrowError(400, 'Invalid User', 'You are not allowed to change password.');
        }

        $userManager = $this->get('fos_user.user_manager');

        $data = $request->request->all();
        $oldPassword = $data['old_password'];
        $password = $data['password'];

        // Check if old password is valid
        // Get the encoder for the users password
        $encoder_service = $this->get('security.encoder_factory');
        $encoder = $encoder_service->getEncoder($user);
        if (!$encoder->isPasswordValid($user->getPassword(), $oldPassword, $user->getSalt()))
        {
            // Password bad
            $this->logAndThrowError(400, 'Invalid old password: '.  $user->getUsername(), $this->get('translator')->trans('api.show_error_password_old', array(), 'messages', $request->getLocale()), $request->getLocale());
        }

        $user->setPlainPassword($password);
        $msg = 'Password changed successfully';

        $userManager->updateUser($user);

        $this->logMessage(200, $msg.' for '.$user->getUsername());

        return new JsonResponse(array(
                'code' => 201,
                'show_message' => $msg,
                'username' => $user->getUsername(),
        ));
    }

    /**
      * Fetch User profile detail. Will return a JsonResponse(username...) upon success.
      * Since existing user is verified by access_token, username + old password is not needed.
      *
      *
      * @Post("/user/profile/show")
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Fetch User profile detail. Access token to be provided in header (Authorization = Bearer <access token>)",
      *  parameters={
      *      {"name"="_locale", "dataType"="string", "required"=false, "description"="User locale. Will default to en"}
      *  },
      * )
      */
    public function getProfileAction()
    {
        $request = $this->container->get('request');

        $user = $this->container->get('security.context')->getToken()->getUser();
        if (!is_object($user) || !$user instanceof UserInterface) {
            $this->logAndThrowError(400, 'Invalid User', $this->get('translator')->trans('api.show_error_perm_show', array(), 'messages', $request->getLocale()), $request->getLocale());
        }

        // Check if dob is valid
        if ($user->dobString() == "Null Date of Birth" || $user->dobString() == "Malformed date of birth") {
            $dobString = '';
            $this->logMessage(400, 'Invalid or null DOB: '.$user->dobString().' for '.$user->getUsername());
        } else {
            $dobString = $user->dobString();
        }

        $this->logMessage(200, 'Profile fetched successfully for '.$user->getUsername());

        return new JsonResponse(array(
          'code' => 201,
          'show_message' => 'Profile fetched successfully',
          'username' => $user->getUsername(),
          'firstname' => $user->getFirstname(),
          'lastname' => $user->getLastname(),
          'dob' => $dobString,
          'email' => $user->getEmail()
        ));
    }

    /**
      * Update User profile detail. Will return a JsonResponse(username, msg) upon success. Since existing
      * user is verified by access_token, username + old password is not needed.
      *
      * @Post("/user/profile/edit")
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Update User profile detail. Access token to be provided in header (Authorization = Bearer <access token>)",
      *  parameters={
      *      {"name"="username", "dataType"="string", "required"=true, "description"="username, leave null if unchanged"},
      *      {"name"="firstname", "dataType"="string", "required"=true, "description"="firstname, leave null if unchanged"},
      *      {"name"="lastname", "dataType"="string", "required"=true, "description"="lastname, leave null if unchanged"},
      *      {"name"="dob", "dataType"="datetime", "required"=true, "description"="date of birth mm/dd/yyyy, leave null if unchanged"},
      *      {"name"="email", "dataType"="email", "required"=true, "description"="Email, leave null if unchanged"},
      *      {"name"="_locale", "dataType"="string", "required"=false, "description"="User locale. Will default to en"}
      *  },
      * )
      */
    public function editProfileAction()
    {
        $request = $this->container->get('request');

        $user = $this->container->get('security.context')->getToken()->getUser();
        if (!is_object($user) || !$user instanceof UserInterface) {
            $this->logAndThrowError(400, 'Invalid User', $this->get('translator')->trans('api.show_error_perm_edit', array(), 'messages', $request->getLocale()), $request->getLocale());
        }

        $userManager = $this->get('fos_user.user_manager');

        $data = $request->request->all();

        $this->handleKeyUsername($user, $request);
        $this->handleKeyEmail($user, $request);
        $this->handleKeyFirstname($user, $request);
        $this->handleKeyLastname($user, $request);
        $this->handleKeyDob($user, $request);

        $userManager->updateUser($user);

        $msg = 'Profile changed successfully';

        $username = $user->getUsername();

        $this->logMessage(201, $msg.' for '.$username);

        return new JsonResponse(array(
          'code' => 201,
          'show_message' => $msg.' for '.$username
        ));
    }

    /**
      * Checks $request if it contains a key - username
      */
    private function handleKeyUsername(UserInterface $user, Request $request) {
      $data = $request->request->all();

      if (array_key_exists('username', $data)) {
        // Change username only if username is changed
        if ($data['username'] != $user->getUsername()) {
          // Check if username is already taken
          $user1 = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($data['username']);
          if (null != $user1) {
            $this->logAndThrowError(400, 'Already taken by Username: '.$user1->getUsername(), $this->get('translator')->trans('api.show_error_username_taken', array(), 'messages', $request->getLocale()), $request->getLocale());
          }
          $user->setUsername($data['username']);
        }
      }
    }

    /**
      * Checks $request if it contains a key - email
      */
    private function handleKeyEmail(UserInterface $user, Request $request) {
      $data = $request->request->all();

      if (array_key_exists('email', $data)) {
        // Check if email is valid
        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            $this->logAndThrowError(400, 'Invalid email: '.$data['email'], 'Invalid email: '.$data['email']);
        }
        // Update email only if email is changed
        if ($data['email'] != $user->getEmail()) {
            // Check if email is already taken
            $user1 = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($data['email']);
            if (null != $user1) {
              $this->logAndThrowError(400, 'Email ' .$user1->getEmail().' already taken by Username: '.$user1->getUsername(), $this->get('translator')->trans('api.show_error_email_taken', array(), 'messages', $request->getLocale()), $request->getLocale());
            }
            $user->setEmail($data['email']);
        }
      }
    }

    /**
      * Checks $request if it contains a key - firstname
      */
    private function handleKeyFirstname(UserInterface $user, Request $request) {
      $data = $request->request->all();

      if (array_key_exists('firstname', $data)) {
        // Check if firstname is empty. At least firstname is required.
        if (null == $data['firstname']) {
            $this->logAndThrowError(400, 'Invalid empty firstname', $this->get('translator')->trans('api.show_error_firstname', array(), 'messages', $request->getLocale()), $request->getLocale());
        }
        $user->setFirstname($data['firstname']);
      }

    }

    /**
      * Checks $request if it contains a key - lastname
      */
    private function handleKeyLastname(UserInterface $user, Request $request) {
      $data = $request->request->all();

      if (array_key_exists('lastname', $data)) {
        $user->setLastname($data['lastname']);
      }
    }

    /**
      * Checks $request if it contains a key - dob
      */
    private function handleKeyDob(UserInterface $user, Request $request) {
      $data = $request->request->all();

      if (array_key_exists('dob', $data)) {
        // Check if dob is valid
        list($mm,$dd,$yyyy) = array_merge( explode('/',$data['dob']), array(0,0,0) );
        if (!checkdate($mm,$dd,$yyyy)) {
            $this->logAndThrowError(400, 'Invalid mm/dd/yyyy DOB: '.$data['dob'], $this->get('translator')->trans('api.show_error_dob', array(), 'messages', $request->getLocale()), $request->getLocale());
        }
        $user->setDob($data['dob']);
      }

    }

    /**
      * Request reset user password. A mail will be sent, if not sent earlier else will return  error msg.
      *
      *
      * @Get("/user/resetting/request")
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Request reset user password: submit form and send email",
      *  parameters={
      *      {"name"="username", "dataType"="string", "required"=true, "description"="username"},
      *      {"name"="_locale", "dataType"="string", "required"=false, "description"="User locale. Will default to en"}
      *  },
      * )
      */
    public function getResettingRequestAction()
    {
        $request = $this->container->get('request');
        $username = $request->query->get('username');

        /** @var $user UserInterface */
        $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($username);

        if (null === $user) {
            $this->logAndThrowError(400, 'Invalid User', $this->get('translator')->trans('api.show_error_password_reset', array(), 'messages', $request->getLocale()), $request->getLocale());
        }

        if ($user->isPasswordRequestNonExpired($this->container->getParameter('fos_user.resetting.token_ttl'))) {
            $this->logAndThrowError(400, 'Password reset request already received', $this->get('translator')->trans('api.show_error_reset_req', array(), 'messages', $request->getLocale()), $request->getLocale());
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

        $session = $this->container->get('session');
        $email = $session->get(static::SESSION_EMAIL);
        $session->remove(static::SESSION_EMAIL);

        return new JsonResponse(array(
            'code' => 201,
            'show_message' => 'Mail already send to '.$email.'. Please check your mail.'
        ));
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
            $email = '...'.substr($email, $pos);
        }

        $this->logMessage(200, $email);

        return $email;
    }

    /**
      * Get Access Token. Will return a JsonResponse from oAuth upon success.
      *
      *
      * @Post("/user/access/token")
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Request a new Access Token",
      *  parameters={
      *      {"name"="client_id", "dataType"="string", "required"=true, "description"="oAuth ClientId"},
      *      {"name"="client_secret", "dataType"="string", "required"=true, "description"="oAuth ClientSecret"},
      *      {"name"="username", "dataType"="string", "required"=true, "description"="username"},
      *      {"name"="password", "dataType"="string", "required"=true, "description"="password"},
      *      {"name"="scope", "dataType"="string", "required"=true, "description"="Fixed value - API"},
      *      {"name"="_locale", "dataType"="string", "required"=false, "description"="User locale. Will default to en"}
      *  },
      * )
      */
    public function postAccessTokenAction()
    {
        $request = $this->container->get('request');

        $data = $request->request->all();

        $username = $data['username'];
        $password = $data['password'];
        $scope = $data['scope'];
        $clientId = $data['client_id'];
        $clientSecret = $data['client_secret'];
        $grantType = 'password';

        if (!$username || !$password || !$clientId || !$clientSecret || !$scope) {
            $this->logAndThrowError(400, 'Unable to obtain Access Token for missing username/password/clientId/clientSecret.', $this->get('translator')->trans('api.show_error_server_fault', array(), 'messages', $request->getLocale()), $request->getLocale());
        }

        $oAuthRtn = $this->fetchAccessToken($request, $grantType);

        $msg = 'Access Token successfully fetched for '.$username;
        $this->logMessage(201, $msg);

        $oAuthRtn['code'] = 201;
        $oAuthRtn['show_message'] = 'Logged in successfully';

        return new JsonResponse($oAuthRtn);
    }

    /**
      * Get a new Access Token from a Refresh Token. Will return a JsonResponse from oAuth upon success.
      *
      *
      * @Post("/user/refresh/token")
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Request a new Access Token from a Refresh Token",
      *  parameters={
      *      {"name"="client_id", "dataType"="string", "required"=true, "description"="oAuth ClientId"},
      *      {"name"="client_secret", "dataType"="string", "required"=true, "description"="oAuth ClientSecret"},
      *      {"name"="refresh_token", "dataType"="string", "required"=true, "description"="Refresh Token"},
      *      {"name"="_locale", "dataType"="string", "required"=false, "description"="User locale. Will default to en"}
      *  },
      * )
      */
    public function postRefreshTokenAction()
    {
        $request = $this->container->get('request');

        $data = $request->request->all();

        $clientId = $data['client_id'];
        $clientSecret = $data['client_secret'];
        $refreshToken = $data['refresh_token'];
        $grantType = 'refresh_token';

        if (!$refreshToken || !$clientId || !$clientSecret) {
            $this->logAndThrowError(400, 'Unable to obtain Access Token for missing refresh_token/clientId/clientSecret.', $this->get('translator')->trans('api.show_error_server_fault', array(), 'messages', $request->getLocale()), $request->getLocale());
        }

        $oAuthRtn = $this->fetchAccessToken($request, $grantType);

        $msg = 'Access Token successfully fetched on Refresh Token';
        $this->logMessage(201, $msg);

        $oAuthRtn['code'] = 201;
        $oAuthRtn['show_message'] = 'Logged in successfully';

        return new JsonResponse($oAuthRtn);
    }

    /**
      * Fetch oAuth Access Token from oAuth engine.
      *
      */
    private function fetchAccessToken(Request $request, $grantType)
    {
        $request = $this->container->get('request');

        $data = $request->request->all();

        $clientId = $data['client_id'];
        $clientSecret = $data['client_secret'];

        $refreshToken = array_key_exists('refresh_token', $data) ? $data['refresh_token'] : null;
        $username = array_key_exists('username', $data) ? $data['username'] : null;
        $password = array_key_exists('password', $data) ? $data['password'] : null;
        $scope = array_key_exists('scope', $data) ? $data['scope'] : null;

        $client = new OAuth2\Client($clientId, $clientSecret);

        // This is a common function for both getAccessTokenAction() and getRefreshTokenAction().
        // Hence, we need to distinguish between parameters passed.
        if (null != $refreshToken) {
          $params = array('refresh_token' => $refreshToken);
        } else {
          $params = array('username' => $username,
                          'password' => $password,
                          'scope' => $scope
                        );
        }
        $response = $client->getAccessToken($this->container->getParameter('oauth2_token_endpoint'), $grantType, $params);

        $accessToken = 'Total Garbage';

        if (isset($response['result'])) {
          if (isset($response['result']['access_token'])) {
            $accessToken = $response['result']['access_token'];
          } elseif (isset($response['result']['error'])) {
            // If error occurred, then throw an exception, else return the result
            $this->logAndThrowError(400, $response['result']['error'].' - '.$response['result']['error_description'], $this->get('translator')->trans('api.show_error_server_fault', array(), 'messages', $request->getLocale()), $request->getLocale());
          }
        }

        return $response['result'];
    }

    private function logAndThrowError($errCode = 400, $errMsg = 'Bad Request', $showMsg = '', $locale = 'en') {
      $this->logMessage($errCode, $errMsg);
      throw new HttpException($errCode, $errMsg.($showMsg ? '#showme#'.$showMsg : '') );
    }

    private function logMessage($errCode = 200, $logMsg = 'Nil Log Message') {
      $logger = $this->get('logger');
      $logger->info($errCode.' '.$logMsg);
    }
}

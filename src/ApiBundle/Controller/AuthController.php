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

      $this->logMessage(200, 'Users fetched ' . serialize($users));

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
    public function getNewClientAction()
    {
        $entityManager = $this->get('doctrine')->getManager();
        $request = $this->container->get('request');

        $data = $request->request->all();
        $username = $data['username'];
        $password = $data['password'];
        $clientName = $data['name'];
        $redirectUrl = $data['redirect_url'];

        $query = $entityManager->createQuery("SELECT u FROM \ApiBundle\Entity\User u WHERE u.username = :username");
        $query->setParameter('username', $username);
        $user = $query->getOneOrNullResult();

        // Check Client name is not empty
        if (!$clientName) {
            $this->logAndThrowError(400, 'Client Name cannot be empty', $this->get('translator')->trans('action.client_not_empty'), $request->getLocale());
        }

        // Check Redirect URL is not empty
        if (!$redirectUrl) {
            $this->logAndThrowError(400, 'Redirect URL cannot be empty', $this->get('translator')->trans('action.client_redirect_not_empty'), $request->getLocale());
        }

        // Check for the valid Admin user
        if ($user) {
          // Get the encoder for the users password
          $encoder_service = $this->get('security.encoder_factory');
          $encoder = $encoder_service->getEncoder($user);

          if ($encoder->isPasswordValid($user->getPassword(), $password, $user->getSalt())) {
            // Not an Admin
            if (!in_array('ROLE_ADMIN', $user->getRoles())) {
              $this->logAndThrowError(400, 'User is not an Admin: ' . $username, 'Sorry, you are not an Admin!');
            }
          } else {
              // Password bad
              $this->logAndThrowError(400, 'Invalid password: '. $username, 'Sorry, Wrong/Missing Password!');
          }
        } else {
          // Username bad
          $this->logAndThrowError(400, 'Invalid username: ' . $username, 'Sorry, Wrong/Missing Username!');
        }

        // Everything ok, now proceed to create the client
        $clientManager = $this->container->get('fos_oauth_server.client_manager.default');
        $client = $clientManager->createClient();
        $client->setRedirectUris(array($redirectUrl));
        $client->setAllowedGrantTypes(array("authorization_code",
                                            "password",
                                            "refresh_token",
                                            "token",
                                            "client_credentials"
                                      ));

        $clientManager->updateClient($client);

        $this->logMessage(200, 'Client successfully created: ' . $client->getPublicId());

        return new JsonResponse(array(
          'code' => 200,
          'show_message' => 'Client successfully created.',
          'client_id' => $client->getPublicId(),
          'client_secret' => $client->getSecret()
        ));
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
    public function getRegisterAction()
    {
        $userManager = $this->get('fos_user.user_manager');
        $request = $this->container->get('request');

        $data = $request->request->all();

        $clientId = $data['client_id'];
        $clientSecret = $data['client_secret'];

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
            $this->logAndThrowError(400, 'Invalid Client Credentials: ' . $clientId);
        }

        $username = $data['username'];
        $password = $data['password'];
        $email = $data['email'];
        $confirmationEnabled = $data['email_confirmation'];

        $firstname = $data['firstname'];
        $lastname = $data['lastname'];
        $dob = $data['dob'];
        $scope = $data['scope'];

        // Check if password is empty
        if (null == $username) {
            $this->logAndThrowError(400, 'Empty username', 'Sorry, Empty Username!');
        }

        // Do a check for existing user with userManager->findByUsername
        /** @var $user UserInterface */
        $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($username);
        if (null != $user) {
          $this->logAndThrowError(400, 'User already exists. Username: ' . $user->getUsername(), 'Sorry, Username already taken!');
        }

        // Check if password is empty
        if (null == $password) {
            $this->logAndThrowError(400, 'Invalid empty password', 'Sorry, Wrong/Missing Password!');
        }

        // Check if email is valid
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
          $this->logAndThrowError(400, 'Invalid email: ' . $email, 'Sorry, Wrong/Missing Email! ');
        }

        $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($email);
        if (null != $user) {
          $this->logAndThrowError(400, 'Email '  . $user->getEmail() . ' already taken by Username: ' . $user->getUsername(), 'Email '  . $user->getEmail() . ' already taken by Username: ' . $user->getUsername());
        }

        // Check if dob is valid
        list($mm,$dd,$yyyy) = explode('/',$dob);
        if (!checkdate($mm,$dd,$yyyy)) {
            $this->logAndThrowError(400, 'Invalid mm/dd/yyyy DOB: ' . $dob, 'Invalid mm/dd/yyyy DOB: ' . $dob);
        }

        // Check if scope is set to API
        if ('API' != $scope) {
            $this->logAndThrowError(400, 'Invalid scope: ' . $scope, 'Invalid scope: ' . $scope);
        }

        // Check if firstname is empty. At least firstname is required.
        if (null == $firstname) {
            $this->logAndThrowError(400, 'Invalid empty firstname', 'Invalid empty firstname');
        }

        $user = $userManager->createUser();

        $user->setUsername($username);
        $user->setPlainPassword($password);
        $user->setEmail($email);
        $user->setFirstname($firstname);
        $user->setLastname($lastname);
        $user->setDob($dob);
        $user->setRoles(array('ROLE_'.$scope));
        $user->setEnabled(true);

        $userManager->updateUser($user);

        $oAuthRtn = 'Pending';
        $msg = 'N.A.';
        $grantType = 'password';

        if ('1' == $confirmationEnabled) {
            $msg = 'Please check your email to complete the registration.';
        } else {
            $msg = 'Registration complete. Welcome!';
            $oAuthRtn = $this->fetchAccessToken($clientId, $clientSecret,
                                                $grantType, null, $username, $password, $scope);
        }

        $this->logMessage(201, 'User successfully created ' . $username);

        return new JsonResponse(array(
                'code' => 201,
                'show_message' => $msg,
                'username' => $username,
                'oauth' => $oAuthRtn
        ));
    }

    /**
      * Change Password request. Will return a JsonResponse(username, msg) upon success.
      *
      *
      * @Post("/user/change/password")
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
    public function getChangePasswordAction()
    {
        $user = $this->container->get('security.context')->getToken()->getUser();
        if (!is_object($user) || !$user instanceof UserInterface) {
            $this->logAndThrowError(400, 'Invalid User', 'You are not allowed to change password.');
        }

        $userManager = $this->get('fos_user.user_manager');
        $request = $this->container->get('request');

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
            $this->logAndThrowError(400, 'Invalid old password: '.  $user->getUsername(), 'Sorry, Wrong Old Password!');
        }

        $user->setPlainPassword($password);
        $msg = 'Password changed successfully';

        $userManager->updateUser($user);

        $this->logMessage(200, $msg . ' for ' . $user->getUsername());

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
    public function getProfileShowAction()
    {
        $user = $this->container->get('security.context')->getToken()->getUser();
        if (!is_object($user) || !$user instanceof UserInterface) {
            $this->logAndThrowError(400, 'Invalid User', 'You are not permitted to view user profile.');
        }

        // Check if dob is valid
        if ($user->dobString() == "Null Date of Birth" || $user->dobString() == "Malformed date of birth") {
            $dobString = '';
            $this->logMessage(400, 'Invalid or null DOB: ' . $user->dobString() . ' for ' . $user->getUsername());
        } else {
            $dobString = $user->dobString();
        }

        $this->logMessage(200, 'Profile fetched successfully for ' . $user->getUsername());

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
    public function getProfileEditAction()
    {
        $user = $this->container->get('security.context')->getToken()->getUser();
        if (!is_object($user) || !$user instanceof UserInterface) {
            $this->logAndThrowError(400, 'Invalid User', 'You are not permitted to edit user profile.');
        }

        $userManager = $this->get('fos_user.user_manager');
        $request = $this->container->get('request');

        $data = $request->request->all();

        if (array_key_exists('username', $data)) {
          // Change username only if username is changed
          if ($data['username'] != $user->getUsername()) {
            // Check if username is already taken
            $user1 = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($data['username']);
            if (null != $user1) {
              $this->logAndThrowError(400, 'Already taken by Username: ' . $user1->getUsername(), 'Already taken by Username: ' . $user1->getUsername());
            }
            $user->setUsername($data['username']);
          }
        }

        if (array_key_exists('email', $data)) {
          // Check if email is valid
          if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
              $this->logAndThrowError(400, 'Invalid email: ' . $data['email'], 'Invalid email: ' . $data['email']);
          }
          // Update email only if email is changed
          if ($data['email'] != $user->getEmail()) {
              // Check if email is already taken
              $user1 = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($data['email']);
              if (null != $user1) {
                $this->logAndThrowError(400, 'Email '  . $user1->getEmail() . ' already taken by Username: ' . $user1->getUsername(), 'Email '  . $user1->getEmail() . ' already taken by Username: ' . $user1->getUsername());
              }
              $user->setEmail($data['email']);
          }
        }

        if (array_key_exists('firstname', $data)) {
          // Check if firstname is empty. At least firstname is required.
          if (null == $data['firstname']) {
              $this->logAndThrowError(400, 'Invalid empty firstname', 'Invalid empty firstname');
          }
          $user->setFirstname($data['firstname']);
        }

        if (array_key_exists('lastname', $data)) {
          $user->setLastname($data['lastname']);
        }

        if (array_key_exists('dob', $data)) {
          // Check if dob is valid
          list($mm,$dd,$yyyy) = array_merge( explode('/',$data['dob']), array(0,0,0) );
          if (!checkdate($mm,$dd,$yyyy)) {
              $this->logAndThrowError(400, 'Invalid mm/dd/yyyy DOB: ' . $data['dob'], 'Invalid mm/dd/yyyy DOB: ' . $data['dob']);
          }
          $user->setDob($data['dob']);
        }

        $userManager->updateUser($user);

        $msg = 'Profile changed successfully';

        $username = $user->getUsername();

        $this->logMessage(201, $msg . ' for ' . $username);

        return new JsonResponse(array(
          'code' => 201,
          'show_message' => $msg . ' for ' . $username
        ));
    }

    /**
      * Request reset user password. A mail will be sent, if not sent earlier else will return  error msg.
      *
      *
      * @Get("/user/resetting/request/email")
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
    public function getResettingRequestEmailAction()
    {
        $username = $this->container->get('request')->query->get('username');

        /** @var $user UserInterface */
        $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($username);

        if (null === $user) {
            $this->logAndThrowError(400, 'Invalid User', 'You are not permitted to request for password reset.');
        }

        if ($user->isPasswordRequestNonExpired($this->container->getParameter('fos_user.resetting.token_ttl'))) {
            $this->logAndThrowError(400, 'Password reset request already received', 'Password reset request already received');
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
            $email = '...' . substr($email, $pos);
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
    public function getAccessTokenAction()
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
            $this->logAndThrowError(400, 'Unable to obtain Access Token for missing username/password/clientId/clientSecret.');
        }

        $oAuthRtn = $this->fetchAccessToken($clientId, $clientSecret, $grantType, null, $username, $password, $scope);

        $msg = 'Access Token successfully fetched for ' . $username;
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
    public function getRefreshTokenAction()
    {
        $request = $this->container->get('request');

        $data = $request->request->all();

        $clientId = $data['client_id'];
        $clientSecret = $data['client_secret'];
        $refreshToken = $data['refresh_token'];
        $grantType = 'refresh_token';

        if (!$refreshToken || !$clientId || !$clientSecret) {
            $this->logAndThrowError(400, 'Unable to obtain Access Token for missing refresh_token/clientId/clientSecret.');
        }

        $oAuthRtn = $this->fetchAccessToken($clientId, $clientSecret, $grantType, $refreshToken);

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
    private function fetchAccessToken($clientId, $clientSecret, $grantType, $refreshToken = null, $username = null, $password = null, $scope = null)
    {
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
            $this->logAndThrowError(400, $response['result']['error'].' - '.$response['result']['error_description'], $response['result']['error_description']);
          }
        }

        return $response['result'];
    }

    private function logAndThrowError($errCode = 400, $errMsg = 'Bad Request', $showMsg = '', $locale = 'en') {
      $this->logMessage($errCode, $errMsg);
      throw new HttpException($errCode, $errMsg . '#showme#' . '['. $locale . '] ' . $showMsg);
    }

    private function logMessage($errCode = 200, $logMsg = 'Nil Log Message') {
      $logger = $this->get('logger');
      $logger->info($errCode . ' ' . $logMsg);
    }
}

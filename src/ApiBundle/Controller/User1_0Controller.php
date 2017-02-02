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

/**
 * Version({"v1.0."}) - TBD. Not functioning due to a bug in FOSRestBundle.
 *
 * @NamePrefix("api_")
 * @RouteResource("User")
 */
class User1_0Controller extends FOSRestController implements ClassResourceInterface
{
    const SESSION_EMAIL = 'fos_user_send_resetting_email/email';

    /**
      * Fetch all Users.
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Fetch All Users",
      * )
      *
      * Method = GET. Provide this info in user_routes1_0.yml.
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
      * Create a new Client for the given URL. Only to be created by Admin.
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Create a new Client",
      *  parameters={
      *      {"name"="username", "dataType"="string", "required"=true, "description"="Admin username"},
      *      {"name"="password", "dataType"="string", "required"=true, "description"="password"},
      *  },
      * )
      */
    public function getNewClientAction()
    {
        $userManager = $this->get('fos_user.user_manager');
        $entityManager = $this->get('doctrine')->getManager();
        $request = $this->container->get('request');

        $data = $request->request->all();
        $username = $data['username'];
        $password = $data['password'];

        $em = $this->get('doctrine')->getEntityManager();
        $query = $em->createQuery("SELECT u FROM \ApiBundle\Entity\User u WHERE u.username = :username");
        $query->setParameter('username', $username);
        $user = $query->getOneOrNullResult();

        $ifErred = false;

        // First check if we have a valid redirectUrl
        $redirectUrl = $this->container->getParameter('oauth2_redirect_url');
        if (substr($redirectUrl, -1) != '/') {
          $redirectUrl .= '/';
        }
        // Check if this URL actually exists
        $headers = @get_headers($redirectUrl);
        if (strpos($headers[0],'200')=== false) {
          $this->logAndThrowError(400, 'Invalid redirectURL: ' . $redirectUrl);
        }

        // Check for the valid Admin user
        if ($user) {
          // Get the encoder for the users password
          $encoder_service = $this->get('security.encoder_factory');
          $encoder = $encoder_service->getEncoder($user);

          if ($encoder->isPasswordValid($user->getPassword(), $password, $user->getSalt())) {
            // Not an Admin
            if (!in_array('ROLE_ADMIN', $user->getRoles())) {
              $ifErred = true;
              $this->logAndThrowError(400, 'User is not an Admin: ' . $username . '#showme#' . 'Sorry, you are not an Admin!');
            }
          } else {
              // Password bad
              $ifErred = true;
              $this->logAndThrowError(400, 'Invalid password: '. $username . '#showme#' . 'Sorry, Wrong/Missing Password!');
          }
        } else {
          // Username bad
          $ifErred = true;
          $this->logAndThrowError(400, 'Invalid username: ' . $username. $username . '#showme#' . 'Sorry, Wrong/Missing Username!');
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

        $this->logMessage('200 ' . 'Client successfully created: ' . $client->getPublicId());

        return new JsonResponse(array(
          'code' => 200,
          'show_message' => 'Client successfully created.',
          'client_id' => $client->getPublicId(),
          'client_secret' => $client->getSecret()
        ));
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
      *      {"name"="dob", "dataType"="datetime", "required"=true, "description"="date of birth mm/dd/yyyy"},
      *      {"name"="email", "dataType"="email", "required"=true, "description"="Email"},
      *      {"name"="email_confirmation", "dataType"="integer", "required"=true, "description"="0-email confirmation not required, 1-required"},
      *      {"name"="scope", "dataType"="string", "required"=true, "description"="Fixed value - API"}
      *  },
      * )
      */
    public function getRegisterAction()
    {
        // First check if we have a valid redirectUrl
        $redirectUrl = $this->container->getParameter('oauth2_redirect_url');
        if (substr($redirectUrl, -1) != '/') {
          $redirectUrl .= '/';
        }

        // Check if this URL actually exists
        $headers = @get_headers($redirectUrl);
        if (strpos($headers[0],'200')=== false) {
          $this->logAndThrowError(400, 'Invalid redirectURL: ' . $redirectUrl);
        }

        $userManager = $this->get('fos_user.user_manager');
        $entityManager = $this->get('doctrine')->getManager();
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
            $this->logAndThrowError(400, 'Empty username' . '#showme#' . 'Sorry, Empty Username!');
        }

        // Do a check for existing user with userManager->findByUsername
        /** @var $user UserInterface */
        $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($username);
        if (null != $user) {
          $this->logAndThrowError(400, 'User already exists. Username: ' . $user->getUsername() . '#showme#' . 'Sorry, Username already taken!');
        }

        // Check if password is empty
        if (null == $password) {
            $this->logAndThrowError(400, 'Invalid empty password' . '#showme#' . 'Sorry, Wrong/Missing Password!');
        }

        // Check if email is valid
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
          $this->logAndThrowError(400, 'Invalid email: ' . $email . '#showme#' . 'Sorry, Wrong/Missing Email! ');
        }

        $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($email);
        if (null != $user) {
          $this->logAndThrowError(400, 'Email '  . $user->getEmail() . ' already taken by Username: ' . $user->getUsername() . '#showme#' . 'Email '  . $user->getEmail() . ' already taken by Username: ' . $user->getUsername());
        }

        // Check if dob is valid
        list($mm,$dd,$yyyy) = explode('/',$dob);
        if (!checkdate($mm,$dd,$yyyy)) {
            $this->logAndThrowError(400, 'Invalid mm/dd/yyyy DOB: ' . $dob . '#showme#' . 'Invalid mm/dd/yyyy DOB: ' . $dob);
        }

        // Check if scope is set to API
        if ('API' != $scope) {
            $this->logAndThrowError(400, 'Invalid scope: ' . $scope . '#showme#' . 'Invalid scope: ' . $scope);
        }

        // Check if firstname is empty. At least firstname is required.
        if (null == $firstname) {
            $this->logAndThrowError(400, 'Invalid empty firstname' . '#showme#' . 'Invalid empty firstname');
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

        $this->logMessage('201 ' . 'User successfully created ' . $username);

        return new JsonResponse(array(
                'code' => 201,
                'show_message' => $msg,
                'username' => $username,
                'oauth' => $oAuthRtn
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
            $this->logAndThrowError(400, 'Invalid User' . '#showme#' . 'You are not allowed to change password.');
        }

        $userManager = $this->get('fos_user.user_manager');
        $entityManager = $this->get('doctrine')->getManager();
        $request = $this->container->get('request');

        $data = $request->request->all();
        $password = $data['password'];

        $user->setPlainPassword($password);
        $msg = 'Password changed successfully';

        $userManager->updateUser($user);

        $this->logMessage( $msg . ' for ' . $user->getUsername());

        return new JsonResponse(array(
                'code' => 201,
                'show_message' => $msg,
                'username' => $user->getUsername(),
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
        $logger = $this->get('logger');

        $user = $this->container->get('security.context')->getToken()->getUser();
        if (!is_object($user) || !$user instanceof UserInterface) {
            $this->logAndThrowError(400, 'Invalid User' . '#showme#' . 'You are not permitted to view user profile.');
        }

        // Check if dob is valid
        if ($user->dobString() == "Null Date of Birth" || $user->dobString() == "Malformed date of birth") {
            $dobString = '';
            $logger->error('400 ' . 'Invalid or null DOB: ' . $user->dobString() . ' for ' . $user->getUsername());
        } else {
            $dobString = $user->dobString();
        }

        $this->logMessage( 'Profile fetched successfully for ' . $user->getUsername());

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
      * Update User profile detail. Will return a JsonResponse(username, msg) upon success, else
      * will throw ErrorException in html. Since existing user is verified by access_token,
      * username + old password is not needed.
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Update User profile detail",
      *  parameters={
      *      {"name"="access_token", "dataType"="string", "required"=true, "description"="oAuth Access Token"},
      *      {"name"="username", "dataType"="string", "required"=true, "description"="username, leave null if unchanged"},
      *      {"name"="firstname", "dataType"="string", "required"=true, "description"="firstname, leave null if unchanged"},
      *      {"name"="lastname", "dataType"="string", "required"=true, "description"="lastname, leave null if unchanged"},
      *      {"name"="dob", "dataType"="datetime", "required"=true, "description"="date of birth mm/dd/yyyy, leave null if unchanged"},
      *      {"name"="email", "dataType"="email", "required"=true, "description"="Email, leave null if unchanged"},
      *  },
      * )
      */
    public function getProfileEditAction()
    {
        $logger = $this->get('logger');

        $user = $this->container->get('security.context')->getToken()->getUser();
        if (!is_object($user) || !$user instanceof UserInterface) {
            $this->logAndThrowError(400, 'Invalid User' . '#showme#' . 'You are not permitted to edit user profile.');
        }

        $userManager = $this->get('fos_user.user_manager');
        $entityManager = $this->get('doctrine')->getManager();
        $request = $this->container->get('request');

        $data = $request->request->all();

        if ($data['username']) {
          // Check if username is already taken
          $user1 = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($data['username']);
          if (null != $user1) {
            $this->logAndThrowError(400, 'Already taken by Username: ' . $user1->getUsername() . '#showme#' . 'Already taken by Username: ' . $user1->getUsername());
          }
          $user->setUsername($data['username']);
        }

        if ($data['firstname']) {
          // Check if firstname is empty. At least firstname is required.
          if (null == $data['firstname']) {
              $this->logAndThrowError(400, 'Invalid empty firstname' . '#showme#' . 'Invalid empty firstname');
          }
          $user->setFirstname($data['firstname']);
        }

        if ($data['lastname']) {
          $user->setLastname($data['lastname']);
        }

        if ($data['email']) {
          // Check if email is valid
          if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            $this->logAndThrowError(400, 'Invalid email: ' . $data['email'] . '#showme#' . 'Invalid email: ' . $data['email']);
          }

          // Check if email is already taken
          $user1 = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($data['email']);
          if (null != $user1) {
            $this->logAndThrowError(400, 'Email '  . $user1->getEmail() . ' already taken by Username: ' . $user1->getUsername() . '#showme#' . 'Email '  . $user1->getEmail() . ' already taken by Username: ' . $user1->getUsername());
          }
          $user->setEmail($data['email']);
        }

        if ($data['dob']) {
          // Check if dob is valid
          list($mm,$dd,$yyyy) = array_merge( explode('/',$data['dob']), array(0,0,0) );
          if (!checkdate($mm,$dd,$yyyy)) {
              $this->logAndThrowError(400, 'Invalid mm/dd/yyyy DOB: ' . $data['dob'] . '#showme#' . 'Invalid mm/dd/yyyy DOB: ' . $data['dob']);
          }
          $user->setDob($data['dob']);
        }

        $userManager->updateUser($user);

        $msg = 'Profile changed successfully';

        $username = $user->getUsername();

        $this->logMessage($msg . ' for ' . $username);

        return new JsonResponse(array(
          'code' => 201,
          'show_message' => $msg . ' for ' . $username
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
        $username = $this->container->get('request')->query->get('username');

        /** @var $user UserInterface */
        $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($username);

        if (null === $user) {
            $this->logAndThrowError(400, 'Invalid User' . '#showme#' . 'You are not permitted to request for password reset.');
        }

        if ($user->isPasswordRequestNonExpired($this->container->getParameter('fos_user.resetting.token_ttl'))) {
            $this->logAndThrowError(400, 'Password reset request already received' . '#showme#' . 'Password reset request already received');
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
        $logger = $this->get('logger');

        $email = $user->getEmail();
        if (false !== $pos = strpos($email, '@')) {
            $email = '...' . substr($email, $pos);
        }

        $logger->info('200 ' . $email);

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
      *      {"name"="scope", "dataType"="string", "required"=true, "description"="Fixed value - API"}
      *  },
      * )
      */
    public function getAccessTokenAction()
    {
        $logger = $this->get('logger');

        $userManager = $this->get('fos_user.user_manager');
        $entityManager = $this->get('doctrine')->getManager();
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
        $this->logMessage('201 ' . $msg);

        return new JsonResponse(array(
          'code' => 201,
          'show_message' => '', // Not required to show this message to client
          'oauth' => $oAuthRtn
        ));
    }

    /**
      * Get a new Access Token from a Refresh Token. Will return a JsonResponse from oAuth upon success, else
      * will throw ErrorException in html.
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Request an oAuth Access Token from a Refersh Token",
      *  parameters={
      *      {"name"="client_id", "dataType"="string", "required"=true, "description"="oAuth ClientId"},
      *      {"name"="client_secret", "dataType"="string", "required"=true, "description"="oAuth ClientSecret"},
      *      {"name"="refresh_token", "dataType"="string", "required"=true, "description"="Refresh Token"},
      *  },
      * )
      */
    public function getRefreshTokenAction()
    {
        $logger = $this->get('logger');

        $userManager = $this->get('fos_user.user_manager');
        $entityManager = $this->get('doctrine')->getManager();
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
        $this->logMessage('201 ' . $msg);

        return new JsonResponse(array(
          'code' => 201,
          'show_message' => '', // Not required to show this message to client
          'oauth' => $oAuthRtn
        ));
    }

    /**
      * Fetch oAuth Access Token from oAuth engine.
      *
      */
    private function fetchAccessToken($clientId, $clientSecret, $grantType, $refreshToken = null, $username = null, $password = null, $scope = null)
    {
        $logger = $this->get('logger');

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
            $this->logAndThrowError(400, $response['result']['error'].' - '.$response['result']['error_description'] . '#showme#' . $response['result']['error_description']);
          }
        }

        return $response['result'];
    }

    private function logAndThrowError($errCode = 400, $errMsg = 'Bad Request') {
      $logger = $this->get('logger');

      $logger->error($errCode. ' ' . $errMsg);
      throw new HttpException($errCode, $errMsg);
    }

    private function logMessage($logMsg = 'Nil Log Message') {
      $logger = $this->get('logger');

      $logger->info(200 . ' ' . $logMsg);
    }
}

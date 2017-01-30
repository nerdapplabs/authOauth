<?php

namespace ApiBundle\Controller;

use ApiBundle\Entity\User;
use ApiBundle\Form\UserType;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use FOS\RestBundle\Controller\Annotations\RouteResource;
use Symfony\Component\HttpFoundation\JsonResponse;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;

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
 * Version({"v1", "v2"}) - Remove this line or Put @ before Version, after a versioning strategy is finalized
 * @NamePrefix("api_")
 */
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

        $method = $this->get('request')->getMethod();
        if ('GET' === $method) {
          $data = $request->query->all();
        } else {
          $data = $request->request->all();
        }
        $username = $data['username'];
        $password = $data['password'];

        $em = $this->get('doctrine')->getEntityManager();
        $query = $em->createQuery("SELECT u FROM \ApiBundle\Entity\User u WHERE u.username = :username");
        $query->setParameter('username', $username);
        $user = $query->getOneOrNullResult();

        $ifErred = false;

        // First check if we have a valid redirectUrl
        $redirectUrl = $this->container->getParameter('oauth2_redirect_url');
        // Check if this URL actually exists
        $headers = @get_headers($redirectUrl);
        if (strpos($headers[0],'200')=== false) {
          throw new HttpException(400, 'Invalid redirectURL: ' . $redirectUrl);
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
              throw new HttpException(400, 'User is not an Admin: ' . $username);
            }
          } else {
              // Password bad
              $ifErred = true;
              throw new HttpException(400, 'Invalid password: '. $username);
          }
        } else {
          // Username bad
          $ifErred = true;
          throw new HttpException(400, 'Invalid username: ' . $username);
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

        return new JsonResponse(array(
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
      *      {"name"="dob", "dataType"="datetime", "required"=true, "description"="date of birth"},
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
        // Check if this URL actually exists
        $headers = @get_headers($redirectUrl);
        if (strpos($headers[0],'200')=== false) {
          throw new HttpException(400, 'Invalid redirectURL: ' . $redirectUrl);
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
            throw new HttpException(400, 'Invalid Client Credentials: ' . $clientId);
        }

        $username = $data['username'];
        $password = $data['password'];
        $email = $data['email'];
        $confirmationEnabled = $data['email_confirmation'];

        $firstname = $data['firstname'];
        $lastname = $data['lastname'];
        $dob = $data['dob'];
        $scope = $data['scope'];

        // Do a check for existing user with userManager->findByUsername
        /** @var $user UserInterface */
        $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($username);
        if (null != $user) {
          throw new HttpException(400, 'User already exists. Username: ' . $user->getUsername());
        }

        // Check if password is empty
        if (null == $password) {
            throw new HttpException(400, 'Invalid empty password');
        }

        // Check if email is valid
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
          throw new HttpException(400, 'Invalid email: ' . $email);
        }

        $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($email);
        if (null != $user) {
          throw new HttpException(400, 'Email '  . $user->getEmail() . ' already taken by Username: ' . $user->getUsername());
        }

        // Check if dob is valid
        list($mm,$dd,$yyyy) = explode('/',$dob);
        if (!checkdate($mm,$dd,$yyyy)) {
            throw new HttpException(400, 'Invalid mm/dd/yyyy DOB: ' . $dob);
        }

        // Check if scope is set to API
        if ('API' != $scope) {
            throw new HttpException(400, 'Invalid scope: ' . $scope);
        }

        // Check if firstname is empty. At least firstname is required.
        if (null == $firstname) {
            throw new HttpException(400, 'Invalid empty firstname');
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

        return new JsonResponse(array(
                'code' => 201,
                'message' => $msg,
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
            throw new HttpException(400, 'invalid User or this user does not have access to this section.');
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
            throw new HttpException(400, 'This user does not have access to this section.');
        }

        return new JsonResponse(array(
          'username' => $user->getUsername(),
          'firstname' => $user->getFirstname(),
          'lastname' => $user->getLastname(),
          'dob' => $user->dobString(),
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
            throw new HttpException(400, 'This user does not have access to this section.');
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

        if ($data['username']) {
          $user->setUsername($data['username']);
        }
        if ($data['firstname']) {
          $user->setFirstname($data['firstname']);
        }
        if ($data['lastname']) {
          $user->setLastname($data['lastname']);
        }
        if ($data['email']) {
          $user->setEmail($data['email']);
        }
        if ($data['dob']) {
          $user->setDob($data['dob']);
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
            throw new HttpException(400, 'This user does not have access to this section.');
        }

        if ($user->isPasswordRequestNonExpired($this->container->getParameter('fos_user.resetting.token_ttl'))) {
            throw new HttpException(400, 'Password reset request already received');
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
      *      {"name"="scope", "dataType"="string", "required"=true, "description"="Fixed value - API"}
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
        $scope = $data['scope'];
        $clientId = $data['client_id'];
        $clientSecret = $data['client_secret'];
        $grantType = 'password';

        if (!$username || !$password || !$clientId || !$clientSecret) {
            throw new HttpException(400, 'Unable to obtain Access Token for missing username/password/clientId/clientSecret.');
        }

        return new JsonResponse($this->fetchAccessToken($clientId, $clientSecret, $grantType, null, $username, $password, $scope));
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
        $userManager = $this->get('fos_user.user_manager');
        $entityManager = $this->get('doctrine')->getManager();
        $request = $this->container->get('request');

        $method = $this->get('request')->getMethod();
        if ('GET' === $method) {
          $data = $request->query->all();
        } else {
          $data = $request->request->all();
        }

        $clientId = $data['client_id'];
        $clientSecret = $data['client_secret'];
        $refreshToken = $data['refresh_token'];
        $grantType = 'refresh_token';

        if (!$refreshToken || !$clientId || !$clientSecret) {
            throw new HttpException(400, 'Unable to obtain Access Token for missing refresh token/clientId/clientSecret.');
        }

        return new JsonResponse($this->fetchAccessToken($clientId, $clientSecret, $grantType, $refreshToken));
    }

    /**
      * Fetch oAuth Access Token from oAuth engine.
      *
      */
    private function fetchAccessToken($clientId, $clientSecret, $grantType, $refreshToken = null, $username = null, $password = null, $scope = null)
    {
        $client = new OAuth2\Client($clientId, $clientSecret);
        if ('refresh_token' == $grantType) {
          $params = array('refresh_token' => $refreshToken
                        );
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
            throw new HttpException(400, $response['result']['error'].' - '.$response['result']['error_description']);
          }
        }

        return $response['result'];
    }
}

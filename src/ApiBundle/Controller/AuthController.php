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
use Symfony\Component\HttpFoundation\File\Exception\UploadException;
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

use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\File\File;

use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;

use Symfony\Component\Validator\Constraints as Assert;

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
      * Fetch all Users.use Symfony\Component\HttpFoundation\File\UploadedFile;
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
      *      {"name"="username", "dataType"="string", "required"=true, "description"="Username should be 3-16 characters long with any lowercase letter (a-z), number (0-9), an underscore, or a hyphen"},
      *      {"name"="password", "dataType"="string", "required"=true, "description"="Password 6-20 characters, at least 1 Uppercase, 1 Lowercase, 1 Number and 1 Special Character"},
      *      {"name"="firstname", "dataType"="string", "required"=true, "description"="firstname"},
      *      {"name"="lastname", "dataType"="string", "required"=true, "description"="lastname"},
      *      {"name"="dob", "dataType"="datetime", "required"=true, "description"="date of birth mm/dd/yyyy"},
      *      {"name"="email", "dataType"="email", "required"=true, "description"="Email"},
      *      {"name"="image", "dataType"="image/jpeg, image/jpg, image/gif, image/png", "required"=false, "description"="Profile Picture within 1024k size"},
      *      {"name"="_locale", "dataType"="string", "required"=false, "description"="User locale. Will default to en"}
      *  },
      * )
      */
    public function postRegisterAction(Request $request)
    {
        $confirmationEnabled = $this->container->getParameter('registration_requires_email_confirmation');
        $request = $this->container->get('request');

        $userManager = $this->get('fos_user.user_manager');
        $user = $userManager->createUser();

        // Validate Client credentials
        $this->validateClient($request);

        // Set User data which will also return Image Validation errors, if any
        $validationErrorsImage = $this->setUserData($request, $user);

        // If Image Validtion returns error, then return errors
        if ( $validationErrorsImage ) {
           return $validationErrorsImage;
        }

        // Validate rest of the input data
        $validationGroups = array('Registration');
        $validationErrors = $this->reportValidationErrors($user, $validationGroups, $request->getLocale());

        // If Validtion returns error, then return errors
        if ( $validationErrors ) {
           return $validationErrors;
        }

        // Everything ok, now write the user record
        $userManager->updateUser($user);

        // Now fetch Access Token
        $oAuthRtn = 'Pending';
        $msg = 'N.A.';
        $grantType = 'password';

        if (true == $confirmationEnabled ) {
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
      *      {"name"="password", "dataType"="string", "required"=true, "description"="Password 6-20 characters, at least 1 Uppercase, 1 Lowercase, 1 Number and 1 Special Character"},
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

        $data = $request->request->all();
        $oldPassword = $data['old_password'];
        $password = $data['password'];

        // First validate old password. If found invalid, return from point with error message
        $this->validateOldPassword($user, $oldPassword, $request->getLocale());

        // Set data for next validation
        $user->setPlainPassword($password);

        // Validate
        $validationGroups = array('profile_edit_password');
        $validationErrors = $this->reportValidationErrors($user, $validationGroups, $request->getLocale());

        // If Validtion returns error, then return errors
        if ( $validationErrors ) {
           return $validationErrors;
        }

        // Now all ok
        $userManager = $this->get('fos_user.user_manager');
        $userManager->updateUser($user);
        $msg = 'Password changed successfully';

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
          'email' => $user->getEmail(),
          'image_url' => $this->getParameter('images_profile_dir').$user->getImage()
        ));
    }

    /**
      * Fetch User profile picture.
      *
      * @Post("/user/profile/get-pic")
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Fetch User profile detail. Access token to be provided in header (Authorization = Bearer <access token>)",
      *  parameters={
      *      {"name"="_locale", "dataType"="string", "required"=false, "description"="User locale. Will default to en"}
      *  },
      * )
      */
    public function getProfilePicAction()
    {
        $request = $this->container->get('request');

        $user = $this->container->get('security.context')->getToken()->getUser();
        if (!is_object($user) || !$user instanceof UserInterface) {
            $this->logAndThrowError(400, 'Invalid User', $this->get('translator')->trans('api.show_error_perm_show', array(), 'messages', $request->getLocale()), $request->getLocale());
        }

        $file = $user->getImage() ? new File($this->getParameter('images_profile_path').$user->getImage()) : null;

        $response = new BinaryFileResponse($file);
        $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT);

        return $response;
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
      *      {"name"="firstname", "dataType"="string", "required"=true, "description"="firstname, leave null if unchanged"},
      *      {"name"="lastname", "dataType"="string", "required"=true, "description"="lastname, leave null if unchanged"},
      *      {"name"="dob", "dataType"="datetime", "required"=true, "description"="date of birth mm/dd/yyyy, leave null if unchanged"},
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

        // Set User data to ve validated next
        $this->setUserProfileData($request, $user);

        // Validate
        $validationGroups = array('profile_edit');
        $validationErrors = $this->reportValidationErrors($user, $validationGroups, $request->getLocale());

        // If Validtion returns error, then return errors
        if ( $validationErrors ) {
           return $validationErrors;
        }

        // Everything ok, now update the user record
        $userManager = $this->get('fos_user.user_manager');
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
      * Fetch User profile picture.
      *
      * @Post("/user/profile/edit-pic")
      *
      * @ApiDoc(
      *  resource=true,
      *  description="Fetch User profile detail. Access token to be provided in header (Authorization = Bearer <access token>)",
      *  parameters={
      *      {"name"="image", "dataType"="image/jpeg, image/jpg, image/gif, image/png", "required"=false, "description"="Profile Picture within 1024k size"},
      *      {"name"="_locale", "dataType"="string", "required"=false, "description"="User locale. Will default to en"}
      *  },
      * )
      */
    public function editProfilePicAction()
    {
        $request = $this->container->get('request');

        $user = $this->container->get('security.context')->getToken()->getUser();
        if (!is_object($user) || !$user instanceof UserInterface) {
            $this->logAndThrowError(400, 'Invalid User', $this->get('translator')->trans('api.show_error_perm_show', array(), 'messages', $request->getLocale()), $request->getLocale());
        }

        // Set User data which will also return Image Validation errors, if any
        $validationErrors = $this->setUserPicData($request, $user);

        // If Image Validtion returns error, then return errors
        if ( $validationErrors ) {
           return $validationErrors;
        }

        // Everything ok, now update Profile Pic
        $userManager = $this->get('fos_user.user_manager');
        $userManager->updateUser($user);

        $msg = 'Profile Pic updated successfully. '.$user->getUsername();
        $this->logMessage(201, $msg);

        return new JsonResponse(array(
                'code' => 201,
                'show_message' => $msg,
                'image_url' => $this->getParameter('images_profile_dir').$user->getImage()
        ));
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
      *      {"name"="_locale", "dataType"="string", "required"=false, "description"="User locale. Will default to en"}
      *  },
      * )
      */
    public function postAccessTokenAction()
    {
        $request = $this->container->get('request');

        $data = $request->request->all();

        $grantType = 'password';

        if (!$data['username'] || !$data['password'] || !$data['client_id'] || !$data['client_secret']) {
            $this->logAndThrowError(400, 'Unable to obtain Access Token for missing username/password/clientId/clientSecret.', $this->get('translator')->trans('api.show_error_server_fault', array(), 'messages', $request->getLocale()), $request->getLocale());
        }

        $oAuthRtn = $this->fetchAccessToken($request, $grantType);

        $msg = 'Access Token successfully fetched for '.$data['username'];
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

        $grantType = 'refresh_token';

        if (!$data['refresh_token'] || !$data['client_id'] || !$data['client_secret']) {
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

        $client = new OAuth2\Client($clientId, $clientSecret);

        // This is a common function for both getAccessTokenAction() and getRefreshTokenAction().
        // Hence, we need to distinguish between parameters passed.
        if (null != $refreshToken) {
          $params = array('refresh_token' => $refreshToken);
        } else {
          $params = array('username' => $username,
                          'password' => $password
                        );
        }
        $response = $client->getAccessToken($this->container->getParameter('oauth2_token_endpoint'), $grantType, $params);

        $accessToken = 'Total Garbage';

        if (isset($response['result'])) {
          if (isset($response['result']['access_token'])) {
            $accessToken = $response['result']['access_token'];
          } elseif (isset($response['result']['error'])) {
            // If error occurred, then throw an exception, else return the result
            $this->logAndThrowError(400, $response['result']['error'].' - '.$response['result']['error_description'], $response['result']['error_description'] );
          }
        }

        return $response['result'];
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

    private function validateOldPassword(User $user, $oldPassword, $locale)
    {
        // Check if old password is valid
        // Get the encoder for the users password
        $encoder_service = $this->get('security.encoder_factory');
        $encoder = $encoder_service->getEncoder($user);
        if (!$encoder->isPasswordValid($user->getPassword(), $oldPassword, $user->getSalt()))
        {
            // Password bad
            $this->logAndThrowError(400, 'Invalid old password: '.  $user->getUsername(), $this->get('translator')->trans('api.show_error_password_old', array(), 'messages', $locale ), $locale );
        }
    }

    private function setUserData(Request $request, User $user)
    {
        // Set User data which will also return Validation errors, if any
        $validationErrors = $this->setUserPicData($request, $user);

        // If Validtion returns error, then return errors
        if ( $validationErrors ) {
           return $validationErrors;
        }

        $user->setUsername($request->request->get('username'));
        $user->setPlainPassword($request->request->get('password'));
        $user->setEmail($request->request->get('email'));
        $user->setFirstname($request->request->get('firstname'));
        $user->setLastname($request->request->get('lastname'));
        $user->setDob($request->request->get('dob'));
        $user->setRoles(array('ROLE_API'));
        $user->setEnabled(true);

        // TODO: Why this validation is not working in Validation.yml for dob
        // This check has to be done here as invalid dob will throw error in setUserData()
        $timestamp = strtotime($request->request->get('dob'));
        if (!$timestamp) {
            $this->logAndThrowError(400, 'Date of Birth should be in MM/DD/YYYY format.', $this->get('translator')->trans('api.show_error_dob', array(), 'messages', $request->getLocale()), $request->getLocale());
        }

        // return null to indicate success
        return null;
    }

    private function setUserPicData(Request $request, User $user)
    {
        $locale = $request->getLocale();

        // $file stores the uploaded Image file
        /** @var Symfony\Component\HttpFoundation\File\UploadedFile $file */
        $file = $request->files->get('image');

        // File is Valid. Now save it.
        if ( null != $file ) {
            // First validate uploaded image. If errors found, return errors
            $imageErrors = $this->validateImage($request);
            if ( $imageErrors ) {
                return $imageErrors;
            }

            // Generate a unique name for the file before saving it
            $fileName = md5(uniqid()).'.'.$file->guessExtension();

            // Move the file to the directory where images are stored
            $file->move($this->getParameter('images_profile_path'), $fileName );

            // Update the 'image' property to store the Image file name
            // instead of its contents
            $user->setImage($fileName);
        }

        // Null is returned to indicate no errors
        return null;
    }

    private function validateImage(Request $request)
    {
        $locale = $request->getLocale();

        // $file stores the uploaded Image file
        /** @var Symfony\Component\HttpFoundation\File\UploadedFile $file */
        $file = $request->files->get('image');

        $imageConstraint = new Assert\Image();

        // all constraint "options" can be set this way
        $imageConstraint->mimeTypes = ["image/jpeg", "image/jpg", "image/gif", "image/png"];
        $imageConstraint->mimeTypesMessage = 'Please upload a valid Image (jpeg/jpg/gif/png only within 1024k size';
        $imageConstraint->maxSize = 1024*1024;
        $imageConstraint->minWidth = 100;
        $imageConstraint->minHeight = 100;
        $imageConstraint->payload['api_error'] = 'api.show_error_image';

        // use the validator to validate the value
        $errors = $this->get('validator')->validate($file, $imageConstraint );

        // If no errors, then return null
        if (!count($errors)) {
           return null;
        }

        $this->logMessage(400, 'Error count '.count($errors) );

        // this is *not* a valid image
        $errorArray = [];
        foreach ($errors as $error) {
            $constraint = $error->getConstraint();
            $errorItem = array(
                                "error_description" => $error->getPropertyPath().': '.$error->getMessage().' '.$error->getInvalidValue(),
                                "show_message" => $this->get('translator')->trans($constraint->payload['api_error'], array(), 'messages', $locale)
                              );
            array_push($errorArray, $errorItem);
            $this->logMessage(400, $errorItem['error_description'] );
        }

        return new JsonResponse(array(
                      "code" => 400,
                      "error" =>  "Bad Request",
                      "error_description" => $errorArray[0]['error_description'],
                      "show_message" => $errorArray[0]['show_message'],
                      'errors' => $errorArray
        ));
    }

    private function setUserProfileData(Request $request, User $user)
    {
        $data = $request->request->all();

        $firstname = array_key_exists('firstname', $data) ? $data['firstname'] : $user->getFirstname();
        $user->setFirstname($firstname);

        $lastname = array_key_exists('lastname', $data) ? $data['lastname'] : $user->getLastname();
        $user->setLastname($lastname);

        $dob = array_key_exists('dob', $data) ? $data['dob'] : $user->getDob();
        $user->setDob($dob);

        // TODO: Why this validation is not working in Validation.yml for dob
        $timestamp = strtotime($dob);
        if ($dob && !$timestamp) {
          $this->logAndThrowError(400, 'Date of Birth should be in MM/DD/YYYY format.', $this->get('translator')->trans('api.show_error_dob', array(), 'messages', $request->getLocale()), $request->getLocale());
        }
    }

    private function reportValidationErrors(User $user, $validationGroups, $locale)
    {
        // Validate user data
        $validator = $this->get('validator');
        $errors = $validator->validate($user, null, $validationGroups);

        // If no errors, then return null
        if (!count($errors)) {
           return null;
        }

        $errorArray = [];
        foreach ($errors as $error) {
            $constraint = $error->getConstraint();
            $errorItem = array(
                                "error_description" => $error->getPropertyPath().': '.$error->getMessage().' '.$error->getInvalidValue(),
                                "show_message" => $this->get('translator')->trans($constraint->payload['api_error'], array(), 'messages', $locale)
                              );
            array_push($errorArray, $errorItem);
            $this->logMessage(400, $errorItem['error_description'] );
        }
        return new JsonResponse(array(
                      "code" => 400,
                      "error" =>  "Bad Request",
                      "error_description" => $errorArray[0]['error_description'],
                      "show_message" => $errorArray[0]['show_message'],
                      'errors' => $errorArray
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
            $email = substr($email, 0,1).'...'.substr($email, $pos-1);
        }

        $this->logMessage(200, $email);

        return $email;
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

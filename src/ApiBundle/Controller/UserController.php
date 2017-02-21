<?php

namespace ApiBundle\Controller;

use ApiBundle\Entity\User;
use ApiBundle\Form\UserType;
use ApiBundle\Form\UserProfileType;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;

use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\HttpFoundation\File\Exception\UploadException;

use Symfony\Component\HttpFoundation\File\File;
use Symfony\Component\HttpFoundation\File\UploadedFile;

use FOS\UserBundle\Model\UserInterface;

/**
 * Controller used to manage user contents in the backend.
 *
 * @Route("/user")
 *
 * @author Amarendra Kumar Sinha <aksinha@nerdapplabs.com>
 */
class UserController extends Controller
{
    /**
     * Lists all User entities.
     *
     * @Route("/", name="user_index")
     * @Method("GET")
     */
    public function indexAction()
    {
      return $this->redirectToRoute('homepage');
    }

    /**
     * Creates a new User entity.
     *
     * @Route("/new", name="user_new")
     * @Method({"GET", "POST"})
     */
    public function newAction(Request $request)
    {
        $confirmationEnabled = $this->container->getParameter('registration_requires_email_confirmation');        $userManager = $this->container->get('fos_user.user_manager');

        $user = $userManager->createUser();
        $user->setRoles(['ROLE_USER']);

        $form = $this->createForm(UserType::class, $user);

        $locale = $request->getLocale();

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            // $file stores the uploaded Image file
            /** @var Symfony\Component\HttpFoundation\File\UploadedFile $file */
            $file = $user->getImage();

            // If a file has been uploaded
            if ( null != $file ) {
                // Generate a unique name for the file before saving it
                $fileName = md5(uniqid()).'.'.$file->guessExtension();

                // Move the file to the directory where images are stored
                $file->move($this->getParameter('images_profile_directory'), $fileName );

                // Update the 'image' property to store the Image file name
                // instead of its contents
                $user->setImage($fileName);
            }

            $this->setUserData($user, $form);

            $userManager->updateUser($user);

            $authUser = false;
            if ($confirmationEnabled) {
                $this->container->get('session')->set('fos_user_send_confirmation_email/email', $user->getEmail());
                $route = 'fos_user_registration_check_email';
            } else {
                $authUser = true;
                $route = 'fos_user_registration_confirmed';
            }

            $this->logMessageAndFlash(200, 'success', 'User successfully created: ', $this->get('translator')->trans('flash.user_created_successfully'), $request->getLocale() );
            $url = $this->container->get('router')->generate($route);
            $response = new RedirectResponse($url);

            if ($authUser) {
                $this->authenticateUser($user, $response);
            }

            return $response;
        }

        return $this->render('@ApiBundle/Resources/views/user/new.html.twig', [
            'form' => $form->createView(),
            'attr' =>  array('enctype' => 'multipart/form-data'),
        ]);
    }

    /**
     * Authenticate a user with Symfony Security
     *
     * @param \FOS\UserBundle\Model\UserInterface        $user
     * @param \Symfony\Component\HttpFoundation\Response $response
     */
    protected function authenticateUser(UserInterface $user, Response $response)
    {
        try {
            $this->container->get('fos_user.security.login_manager')->loginUser(
                $this->container->getParameter('fos_user.firewall_name'),
                $user,
                $response);
        } catch (AccountStatusException $ex) {
            // We simply do not authenticate users which do not pass the user
            // checker (not enabled, expired, etc.).
        }
    }

    /**
     * Finds and displays a User entity.
     *
     * @Route("/profile-show/{id}", name="user_profile_show")
     * @Method("GET")
     */
    public function showAction(User $user)
    {
        return $this->render('@ApiBundle/Resources/views/user/show.html.twig', [
            'user' => $user
        ]);
    }

    /**
     * Displays a form to edit an existing User entity.
     *
     * @Route("/profile-edit/{id}", name="user_profile_edit")
     * @Method({"GET", "POST"})
     */
    public function editAction(User $user, Request $request)
    {
        $entityManager = $this->getDoctrine()->getManager();

        $currentFilename = $user->getImage();
        if ($user->getImage()) {
          $user->setImage(
              new File($this->getParameter('images_profile_directory').'/'.$currentFilename)
          );
        }

        $editForm = $this->createForm(UserProfileType::class, $user);

        $locale = $request->getLocale();

        $editForm->handleRequest($request);

        if ($editForm->isSubmitted() && $editForm->isValid()) {
            // $file stores the uploaded Image file
            /** @var Symfony\Component\HttpFoundation\File\UploadedFile $file */
            $file = $user->getImage();

            // If a file has been uploaded
            if ( null != $file ) {
                // Generate a unique name for the file before saving it
                $fileName = md5(uniqid()).'.'.$file->guessExtension();

                // Move the file to the directory where images are stored
                $file->move($this->getParameter('images_profile_directory'), $fileName );

                // Update the 'image' property to store the Image file name
                // instead of its contents
                $user->setImage($fileName);
            } else {
                $user->setImage($currentFilename);
            }

            $this->setUserProfileData($user, $editForm);

            $entityManager = $this->getDoctrine()->getManager();
            $entityManager->flush();

            $this->logMessageAndFlash(200, 'success', 'User successfully updated: ', $this->get('translator')->trans('flash.user_updated_successfully'), $request->getLocale() );

            $route = 'user_profile_show';
            $url = $this->container->get('router')->generate($route, array('id' => $user->getId()));
            $response = new RedirectResponse($url);

            return $response;
        }

        return $this->render('@ApiBundle/Resources/views/user/edit.html.twig', [
            'user' => $user,
            'current_image' => $currentFilename,
            'edit_form' => $editForm->createView(),
            'attr' =>  array('enctype' => 'multipart/form-data'),
        ]);
    }

    private function setUserData(User $user, \Symfony\Component\Form\Form $form)
    {
      $user->setFirstname($form['firstname']->getData());
      $user->setLastname($form['lastname']->getData());
      $user->setDob($form['dob']->getData());
      $user->setEmail($form['email']->getData());
      $user->setUsername($form['username']->getData());
      $user->setPlainPassword($form['plainPassword']->getData());
      $user->setRoles($form['roles']->getData());
      $user->setConfirmationToken(null);
      $user->setEnabled(true);
      $user->setLastLogin(new \DateTime());
    }

    private function setUserProfileData(User $user, \Symfony\Component\Form\Form $form)
    {
      $user->setFirstname($form['firstname']->getData());
      $user->setLastname($form['lastname']->getData());
      $user->setDob($form['dob']->getData());
      $user->setConfirmationToken(null);
      $user->setEnabled(true);
    }

    private function logMessageAndFlash($code = 200, $type = 'success', $logMsg = '', $flashMsg = '', $locale = 'en')
    {
        $this->logMessage($code, $type, $logMsg);
        $this->addFlash($type, $flashMsg);
    }

    private function logMessage($code = 200, $type='success', $logMsg = '') {
        $logger = $this->get('logger');

        if($type === 'success'){
           $logger->info($code . ' ' . $logMsg);
        } else if($type === 'warning'){
           $logger->warning($code . ' ' . $logMsg);
        }
        else if($type === 'danger'){
           $logger->error($code . ' ' . $logMsg);
        }
    }
}

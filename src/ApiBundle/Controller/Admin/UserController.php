<?php

namespace ApiBundle\Controller\Admin;

use ApiBundle\Entity\User;
use ApiBundle\Form\UserType;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Controller used to manage user contents in the backend.
 *
 * @Route("/admin/user")
 * @Security("has_role('ROLE_ADMIN')")
 *
 * @author Amarendra Kumar Sinha <aksinha@nerdapplabs.com>
 */
class UserController extends Controller
{
    /**
     * Lists all User entities.
     *
     * @Route("/", name="admin_user_index")
     * @Method("GET")
     */
    public function indexAction()
    {
        $repository = $this->getDoctrine()->getRepository('ApiBundle:User');
        $query = $repository->createQueryBuilder('p')
                              ->where('p.enabled = TRUE')
                              ->getQuery();
        $users = $query->getResult();

        return $this->render('@ApiBundle/Resources/views/admin/user/index.html.twig', ['users' => $users]);
    }

    /**
     * Creates a new User entity.
     *
     * @Route("/new", name="admin_user_new")
     * @Method({"GET", "POST"})
     */
    public function newAction(Request $request)
    {
        $user = new User();
        $user->setRoles(['ROLE_USER', 'ROLE_API']);
        $form = $this->createForm(UserType::class, $user);

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
          try {
              $this->validateUsername($form, $request, new User());
              $this->validatePassword($form, $request);
              $this->validateEmail($form, $request, new User());
              $this->validateFirstname($form, $request);
              $this->validateDob($form, $request);
              $this->validateRoles($form, $request);

              // Everything ok, now proceed to create the user
              $userManager = $this->container->get('fos_user.user_manager');
              $user = $userManager->createUser();

              $user->setFirstname($form['firstname']->getData());
              $user->setLastname($form['lastname']->getData());
              $user->setDob($form['dob']->getData());
              $user->setEmail($form['email']->getData());
              $user->setUsername($form['username']->getData());
              $user->setPlainPassword($form['password']->getData());
              $user->setRoles($form['roles']->getData());
              $user->setConfirmationToken(null);
              $user->setEnabled(true);
              $user->setLastLogin(new \DateTime());

              $userManager->updateUser($user);
              $flashMsg = $this->get('translator')->trans('flash.user_created_successfully');
              $this->addFlash('success', $flashMsg);

            } catch(HttpException $e) {
              // Error messages for this section will come from above validate methods
              return $this->redirectToRoute('admin_user_new');

            // Always catch exact exception for which flash message or logger is needed,
            // otherwise catch block will not get executed on higher or lower ranked exceptions.
            } catch(\Doctrine\DBAL\Exception\UniqueConstraintViolationException $e) {
              $flashMsg = $this->get('translator')->trans('flash.user_already_exists');
              $this->logMessage(400, 'danger', $e->getMessage());
              $this->addFlash('danger', $flashMsg);
              return $this->redirectToRoute('admin_user_new');
            }

            return $this->redirectToRoute('admin_user_index');
        } // if form is valid

        return $this->render('@ApiBundle/Resources/views/admin/user/new.html.twig', [
            'form' => $form->createView(),
        ]);
    }

    /**
     * Finds and displays a User entity.
     *
     * @Route("/{id}", name="admin_user_show", requirements={"id": "\d+"})
     * @Method("GET")
     */
    public function showAction(User $user)
    {
        $deleteForm = $this->createDeleteForm($user);

        return $this->render('@ApiBundle/Resources/views/admin/user/show.html.twig', [
            'user' => $user,
            'delete_form' => $deleteForm->createView(),
        ]);
    }

    /**
     * Displays a form to edit an existing User entity.
     *
     * @Route("/edit/{id}", requirements={"id": "\d+"}, name="admin_user_edit")
     * @Method({"GET", "POST"})
     */
    public function editAction(User $user, Request $request)
    {
        $entityManager = $this->getDoctrine()->getManager();

        $editForm = $this->createForm(UserType::class, $user);
        $deleteForm = $this->createDeleteForm($user);

        $editForm->handleRequest($request);

        if ($editForm->isSubmitted() && $editForm->isValid()) {
          try {
                $this->validateUsername($editForm, $request, $user);
                $this->validatePassword($editForm, $request);
                $this->validateEmail($editForm, $request, $user);
                $this->validateFirstname($editForm, $request);
                $this->validateDob($editForm, $request);
                $this->validateRoles($editForm, $request);

                $user->setFirstname($editForm['firstname']->getData());
                $user->setLastname($editForm['lastname']->getData());
                $user->setDob($editForm['dob']->getData());
                $user->setEmail($editForm['email']->getData());
                $user->setUsername($editForm['username']->getData());
                $user->setPlainPassword($editForm['password']->getData());
                $user->setRoles($editForm['roles']->getData());
                $user->setConfirmationToken(null);
                $user->setEnabled(true);
                $user->setLastLogin(new \DateTime());

                $entityManager->flush();
                $flashMsg = $this->get('translator')->trans('flash.user_updated_successfully');
                $this->addFlash('success', $flashMsg);

            // Always catch exact exception for which flash message or logger is needed,
            // otherwise catch block will not get executed on higher or lower ranked exceptions.
            } catch(HttpException $e) {
                // Error messages for this section will come from above validate methods
                return $this->redirectToRoute('admin_user_edit', ['id' => $user->getId()]);
            } catch(\Doctrine\DBAL\Exception\UniqueConstraintViolationException $e) {
                $flashMsg = $this->get('translator')->trans('flash.user_already_exists');
                $this->logMessage(400, 'danger', $e->getMessage());
                $this->addFlash('danger', $flashMsg);
                return $this->redirectToRoute('admin_user_edit', ['id' => $user->getId()]);
            }

            return $this->redirectToRoute('admin_user_index');
        }

        return $this->render('@ApiBundle/Resources/views/admin/user/edit.html.twig', [
            'user' => $user,
            'edit_form' => $editForm->createView(),
            'delete_form' => $deleteForm->createView(),
        ]);
    }

    /**
      * Validate username
      */
    private function validateUsername(\Symfony\Component\Form\Form $form, Request $request, User $user) {
      $username = $form['username']->getData();

      // Check if username is empty
      if (null == $username) {
          $this->logMessageAndFlash(400, 'danger', 'Empty username', $this->get('translator')->trans('api.show_error_username_missing', array(), 'messages', $request->getLocale()), $request->getLocale());
      }

      // If the username belongs to same user, no need to further check
      if (!($user->getUsername() == $username)) {
        // Do a check for existing user with userManager->findByUsername
        /** @var $user UserInterface */
        $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($username);
        if (null != $user) {
          $this->logMessageAndFlash(400, 'danger', 'User already exists. Username: '.$user->getUsername(), $this->get('translator')->trans('api.show_error_username_taken', array(), 'messages', $request->getLocale()), $request->getLocale());
        }
      }
    }

    /**
      * Validate password
      */
    private function validatePassword(\Symfony\Component\Form\Form $form, Request $request) {
      $password = $form['password']->getData();

      // Check if password is empty
      if (null == $password) {
          $this->logMessageAndFlash(400, 'danger', 'Invalid empty password', $this->get('translator')->trans('api.show_error_password', array(), 'messages', $request->getLocale()), $request->getLocale());
      }
    }

    /**
      * Validate email
      */
    private function validateEmail(\Symfony\Component\Form\Form $form, Request $request, User $user) {
      $email = $form['email']->getData();

      // Check if email is valid
      if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $this->logMessageAndFlash(400, 'danger', 'Invalid email: '.$email, $this->get('translator')->trans('api.show_error_email', array(), 'messages', $request->getLocale()), $request->getLocale());
      }

      // If the email belongs to same user, no need to further check
      if (!($user->getEmail() == $email )) {
        $user = $this->container->get('fos_user.user_manager')->findUserByUsernameOrEmail($email);
        if (null != $user) {
          $this->logMessageAndFlash(400, 'danger', 'Email '.$user->getEmail().' already taken by Username: '.$user->getUsername(), $this->get('translator')->trans('api.show_error_email_taken', array(), 'messages', $request->getLocale()), $request->getLocale());
        }
      }
    }

    /**
      * Validate firstname
      */
    private function validateFirstname(\Symfony\Component\Form\Form $form, Request $request) {
      $firstname = $form['firstname']->getData();

      // Check if firstname is empty. At least firstname is required.
      if (null == $firstname) {
          $this->logMessageAndFlash(400, 'danger', 'Invalid empty firstname', $this->get('translator')->trans('api.show_error_firstname', array(), 'messages', $request->getLocale()), $request->getLocale());
      }

    }

    /**
      * Validate dob
      */
    private function validateDob(\Symfony\Component\Form\Form $form, Request $request) {
      $dob = $form['dob']->getData();

      // Check if dob is valid
      list($mm,$dd,$yyyy) = explode('/', $dob->format('m/d/Y') );
      if (!checkdate($mm,$dd,$yyyy)) {
          $this->logMessageAndFlash(400, 'danger', 'Invalid mm/dd/yyyy DOB: '.$dob, $this->get('translator')->trans('api.show_error_dob', array(), 'messages', $request->getLocale()), $request->getLocale());
      }
    }

    /**
      * Validate roles
      */
    private function validateRoles(\Symfony\Component\Form\Form $form, Request $request) {
      $roles = $form['roles']->getData();
      $permittedRoles = ['ROLE_API', "ROLE_USER"];

      foreach ($roles as $role) {
        // Check if role is valid
        if (!in_array($role, $permittedRoles) )
        $this->logMessageAndFlash(400, 'warning', 'Invalid role: '.$role, $this->get('translator')->trans('api.show_error_role'.' '.$role, array(), 'messages', $request->getLocale()), $request->getLocale());
      }
    }

    /**
     * Deletes a User entity.
     *
     * @Route("/delete/{id}", name="admin_user_delete")
     */
    public function deleteAction(Request $request, User $user)
    {
        $entityManager = $this->getDoctrine()->getManager();

        $user->setEnabled(false);
        // $user->setUpdatedAt(new \DateTime());

        $entityManager->flush();

        $flashMsg = $this->get('translator')->trans('flash.user_deleted_successfully');
        $this->logMessage(200, 'success', 'User successfully deleted: ');
        $this->addFlash('success', $flashMsg);

        return $this->redirectToRoute('admin_user_index');
    }

    /**
     * Creates a form to delete a User entity by id.
     *
     * @param User $user The user object
     *
     * @return \Symfony\Component\Form\Form The form
     */
    private function createDeleteForm(User $user)
    {
        return $this->createFormBuilder()
            ->setAction($this->generateUrl('admin_user_delete', ['id' => $user->getId()]))
            ->setMethod('DELETE')
            ->getForm()
        ;
    }

    /**
      * Fetch all Users.
      *
      * @Route("/all", name="admin_users_all")
      * @Method("GET")
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

      $this->logMessage(200, 'success', 'Users fetched');

      return $this->render('@ApiBundle/Resources/views/default/users.html.twig', ['users' => $users]);
    }

    private function logMessageAndFlash($code = 200, $type = 'success', $logMsg = '', $flashMsg = '', $locale = 'en')
    {
        $this->logMessage($code, $type, $logMsg);
        $this->addFlash($type, $flashMsg);
        throw new HttpException($code, $logMsg);
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

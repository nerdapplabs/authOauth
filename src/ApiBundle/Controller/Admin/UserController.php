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
use Symfony\Component\HttpFoundation\File\Exception\UploadException;
use Symfony\Component\HttpFoundation\File\File;
use Symfony\Component\HttpFoundation\File\UploadedFile;

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
        $userManager = $this->container->get('fos_user.user_manager');
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

            $this->logMessageAndFlash(200, 'success', 'User successfully created: ', $this->get('translator')->trans('flash.user_creatd_successfully'), $request->getLocale() );


            return $this->redirectToRoute('admin_user_index');
        }

        return $this->render('@ApiBundle/Resources/views/admin/user/new.html.twig', [
            'form' => $form->createView(),
            'attr' =>  array('enctype' => 'multipart/form-data'),
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

        $currentFilename = $user->getImage();
        if ($user->getImage()) {
          $user->setImage(
              new File($this->getParameter('images_profile_directory').'/'.$currentFilename)
          );
        }

        $editForm = $this->createForm(UserType::class, $user);
        $deleteForm = $this->createDeleteForm($user);
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

            $this->setUserData($user, $editForm);

            $entityManager = $this->getDoctrine()->getManager();
            $entityManager->flush();

            $this->logMessageAndFlash(200, 'success', 'User successfully updated: ', $this->get('translator')->trans('flash.user_updated_successfully'), $request->getLocale() );

            return $this->redirectToRoute('admin_user_index');
        }

        return $this->render('@ApiBundle/Resources/views/admin/user/edit.html.twig', [
            'user' => $user,
            'current_image' => $currentFilename,
            'edit_form' => $editForm->createView(),
            'delete_form' => $deleteForm->createView(),
            'attr' =>  array('enctype' => 'multipart/form-data'),
        ]);
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

        $this->logMessageAndFlash(200, 'success', 'User successfully deleted: ', $this->get('translator')->trans('flash.user_deleted_successfully'), $request->getLocale() );

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

    private function setUserData(User $user, \Symfony\Component\Form\Form $form)
    {
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

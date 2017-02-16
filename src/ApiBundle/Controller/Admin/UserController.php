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
        $locale = $request->getLocale();

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
          try {
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
        $locale = $request->getLocale();

        $editForm->handleRequest($request);

        if ($editForm->isSubmitted() && $editForm->isValid()) {
          try {
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

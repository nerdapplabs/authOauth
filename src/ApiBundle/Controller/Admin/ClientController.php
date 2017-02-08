<?php

namespace ApiBundle\Controller\Admin;

use ApiBundle\Entity\Client;
use ApiBundle\Form\ClientType;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\HttpException;

use OAuth2;

/**
 * Controller used to manage client contents in the backend.
 *
 * @Route("/admin/client")
 * @Security("has_role('ROLE_ADMIN')")
 *
 * @author Amarendra Kumar Sinha <aksinha@nerdapplabs.com>
 */
class ClientController extends Controller
{
    /**
     * Lists all Client entities.
     *
     * @Route("/", name="admin_client_index")
     * @Method("GET")
     */
    public function indexAction()
    {
        $repository = $this->getDoctrine()->getRepository('ApiBundle:Client');
        $query = $repository->createQueryBuilder('p')
                              ->where('p.enabled = TRUE')
                              ->getQuery();
        $clients = $query->getResult();

        return $this->render('@ApiBundle/Resources/views/admin/client/index.html.twig', ['clients' => $clients]);
    }

    /**
     * Creates a new Client entity.
     *
     * @Route("/new", name="admin_client_new")
     * @Method({"GET", "POST"})
     */
    public function newAction(Request $request)
    {
        $data = $request->request->all();
        $clientName = array_key_exists('name', $data) ? $data['name'] : '';
        $redirectUrl = array_key_exists('redirect_url', $data) ? $data['redirect_url'] : '';
        $adminPassword = '';

        $defaultData = array('message' => 'Create a new Client', 'name' => $clientName, 'password' => $adminPassword );

        $form = $this->createFormBuilder()
                ->add('name', 'text', array('label' => 'label.client_name', 'data' => $clientName ))
                ->add('redirect_url', 'text', array('label' => 'label.admin_redirecturl', 'data' => $redirectUrl ))
                ->add('password', 'password', array('label' => 'label.admin_password' ))
                ->add('send', 'submit', array('label' => 'label.create_client' ))
                ->getForm();
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $user = $this->container->get('security.context')->getToken()->getUser();
            $password = $form['password']->getData();

            // Check if Admin password is valid
            // Get the encoder for the users password
            $encoder_service = $this->get('security.encoder_factory');
            $encoder = $encoder_service->getEncoder($user);

            // Password check is an additional security check
            if (!$encoder->isPasswordValid($user->getPassword(), $password, $user->getSalt())) {
                $this->logMessageAndFlash(400, 'danger', 'Invalid Admin password', $this->get('translator')->trans('action.client_invalid_password'));
                return $this->redirectToRoute('admin_client_new');
            }

            // Check Client name is not empty
            if (!$form['name']->getData()) {
                $this->logMessageAndFlash(400, 'danger', 'Client Name cannot be empty', $this->get('translator')->trans('action.client_not_empty'));
                return $this->redirectToRoute('admin_client_new');
            }

            // Check Redirect URL is not empty
            if (!$form['redirect_url']->getData()) {
                $this->logMessageAndFlash(400, 'danger', 'Redirect URL cannot be empty', $this->get('translator')->trans('action.client_redirect_not_empty'));
                return $this->redirectToRoute('admin_client_new');
            }

            // TODO: Check if redirect URL is valid
            // if (!filter_var($form['redirect_url']->getData(), FILTER_VALIDATE_URL)) {
            //   $this->logMessageAndFlash(400, 'danger', 'Invalid Redirect URL: ' . $form['redirect_url']->getData(), 'Invalid Redirect URL: ' . $form['redirect_url']->getData());
            //   return $this->redirectToRoute('admin_client_new');
            // }

            // Everything ok, now proceed to create the client
            $clientManager = $this->container->get('fos_oauth_server.client_manager.default');
            $client = $clientManager->createClient();
            $client->setName($form['name']->getData());
            $client->setRedirectUris(array($form['redirect_url']->getData()));
            $client->setAllowedGrantTypes(array("authorization_code",
                                                "password",
                                                "refresh_token",
                                                "token",
                                                "client_credentials"
                                          ));
            try {
                  $clientManager->updateClient($client);
                  $flashMsg = $this->get('translator')->trans('flash.client_created_successfully');
                  $this->logMessageAndFlash(200, 'success', 'Client successfully created: ' . $client->getPublicId(), $flashMsg);

            // Always catch exact exception for which flash message or logger is needed,
            // otherwise catch block will not get executed on higher or lower ranked exceptions.
            } catch(\Doctrine\DBAL\Exception\UniqueConstraintViolationException $e) {
                  $flashMsg = $this->get('translator')->trans('flash.client_already_exists');
                  $this->logMessageAndFlash(400, 'danger', $e->getMessage(), $flashMsg);
                  return $this->redirectToRoute('admin_client_new');
            }

            return $this->redirectToRoute('admin_client_index');
        } // if form is valid

        return $this->render('@ApiBundle/Resources/views/admin/client/new.html.twig', [
            'form' => $form->createView(),
        ]);
    }

    /**
     * Finds and displays a Client entity.
     *
     * @Route("/{id}", name="admin_client_show")
     * @Method("GET")
     */
    public function showAction(Client $client)
    {
        $deleteForm = $this->createDeleteForm($client);

        return $this->render('@ApiBundle/Resources/views/admin/client/show.html.twig', [
            'client' => $client,
            'delete_form' => $deleteForm->createView(),
        ]);
    }

    /**
     * Displays a form to edit an existing Client entity.
     *
     * @Route("/edit/{id}", requirements={"id": "\d+"}, name="admin_client_edit")
     * @Method({"GET", "POST"})
     */
    public function editAction(Client $client, Request $request)
    {
        $entityManager = $this->getDoctrine()->getManager();

        $defaultData = array('message' => $this->get('translator')->trans('action.edit_client'));
        $editForm = $this->createFormBuilder($defaultData)
                ->add('name', 'text', array('label' => 'label.client_name', 'data' => $client->getName() ))
                ->add('redirect_url', 'text', array('label' => 'label.admin_redirecturl', 'data' => implode($client->getRedirectUris()) ))
                ->add('randomid', 'text', array('label' => 'label.client_randomid', 'data' => $client->getRandomId(), 'disabled' => 'disabled'))
                ->add('secret', 'text', array('label' => 'label.client_secret', 'data' => $client->getSecret(), 'disabled' => 'disabled'))
                ->getForm();

        $deleteForm = $this->createDeleteForm($client);

        $editForm->handleRequest($request);

        if ($editForm->isSubmitted() && $editForm->isValid()) {
            // Check Client name is not empty
            if (!$editForm['name']->getData()) {
                $this->logMessageAndFlash(400, 'danger', 'Client Name cannot be empty', $this->get('translator')->trans('action.client_not_empty'));
                return $this->redirectToRoute('admin_client_edit', ['id' => $client->getId()]);
            }

            // Check Redirect URL is not empty
            if (!$editForm['redirect_url']->getData()) {
                $this->logMessageAndFlash(400, 'danger', 'Redirect URL cannot be empty', $this->get('translator')->trans('action.client_redirect_not_empty'));
                return $this->redirectToRoute('admin_client_edit', ['id' => $client->getId()]);
            }

            // TODO: Check if redirect URL is valid
            // if (!filter_var($form['redirect_url']->getData(), FILTER_VALIDATE_URL)) {
            //   $this->logMessageAndFlash(400, 'danger', 'Invalid Redirect URL: ' . $form['redirect_url']->getData(), 'Invalid Redirect URL: ' . $form['redirect_url']->getData());
            //   return $this->redirectToRoute('admin_client_new');
            // }

            $client->setName($editForm['name']->getData());
            $client->setRedirectUris(array($editForm['redirect_url']->getData()));
            $client->setUpdatedAt(new \DateTime());

            try {
                  $entityManager->flush();
                  $flashMsg = $this->get('translator')->trans('flash.client_updated_successfully');
                  $this->logMessageAndFlash(200, 'success', 'Client successfully updated: ' . $client->getPublicId(), $flashMsg);

            // Always catch exact exception for which flash message or logger is needed,
            // otherwise catch block will not get executed on higher or lower ranked exceptions.
            } catch(\Doctrine\DBAL\Exception\UniqueConstraintViolationException $e) {
                  $flashMsg = $this->get('translator')->trans('flash.client_already_exists');
                  $this->logMessageAndFlash(400, 'danger', $e->getMessage(), $flashMsg);
                  return $this->redirectToRoute('admin_client_edit', ['id' => $client->getId()]);
            }

            return $this->redirectToRoute('admin_client_index');
        }

        return $this->render('@ApiBundle/Resources/views/admin/client/edit.html.twig', [
            'client' => $client,
            'edit_form' => $editForm->createView(),
            'delete_form' => $deleteForm->createView(),
        ]);
    }

    /**
     * Deletes a Client entity.
     *
     * @Route("/delete/{id}", name="admin_client_delete")
     */
    public function deleteAction(Request $request, Client $client)
    {
        $entityManager = $this->getDoctrine()->getManager();

        $client->setEnabled(false);
        $client->setUpdatedAt(new \DateTime());

        $entityManager->flush();

        $flashMsg = $this->get('translator')->trans('flash.client_deleted_successfully');
        $this->logMessageAndFlash(200, 'success', 'Client successfully deleted: ' . $client->getPublicId(), $flashMsg);

        return $this->redirectToRoute('admin_client_index');
    }

    /**
     * Creates a form to delete a Client entity by id.
     *
     * @param Client $client The client object
     *
     * @return \Symfony\Component\Form\Form The form
     */
    private function createDeleteForm(Client $client)
    {
        return $this->createFormBuilder()
            ->setAction($this->generateUrl('admin_client_delete', ['id' => $client->getId()]))
            ->setMethod('DELETE')
            ->getForm()
        ;
    }

    private function logMessageAndFlash($code = 200, $type = 'success', $logMsg = '', $flashMsg = '')
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

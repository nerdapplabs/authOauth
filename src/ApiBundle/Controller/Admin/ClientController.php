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
        $defaultData = array('message' => 'Create a new Client');
        $form = $this->createFormBuilder($defaultData)
                ->add('name', 'text', array('label' => 'label.client_name' ))
                ->add('password', 'password', array('label' => 'label.admin_password' ))
                ->add('send', 'submit', array('label' => 'label.create_client' ))
                ->getForm();
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {

            $user = $this->container->get('security.context')->getToken()->getUser();
            $username = $user->getUsername();
            $password = $form['password']->getData();

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
            $client->setName($form['name']->getData());
            $client->setRedirectUris(array($redirectUrl));
            $client->setAllowedGrantTypes(array("authorization_code",
                                                "password",
                                                "refresh_token",
                                                "token",
                                                "client_credentials"
                                          ));

            $clientManager->updateClient($client);

            $this->logMessage('200 ' . 'Client successfully created: ' . $client->getPublicId());

            $this->addFlash('success', 'client.created_successfully');

            return $this->redirectToRoute('admin_client_index');
        }

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

        $defaultData = array('message' => 'Edit a Client');
        $editForm = $this->createFormBuilder($defaultData)
                ->add('name', 'text', array('label' => 'label.client_name', 'data' => $client->getName() ))
                ->add('randomid', 'text', array('label' => 'label.client_randomid', 'data' => $client->getRandomId(), 'disabled' => 'disabled'))
                ->add('secret', 'text', array('label' => 'label.client_secret', 'data' => $client->getSecret(), 'disabled' => 'disabled'))
                ->getForm();

        $deleteForm = $this->createDeleteForm($client);

        $editForm->handleRequest($request);

        if ($editForm->isSubmitted() && $editForm->isValid()) {
            $client->setName($editForm['name']->getData());
            $client->setUpdatedAt(new \DateTime());

            $entityManager->flush();

            $this->addFlash('success', 'client.updated_successfully');

            return $this->redirectToRoute('admin_client_edit', ['id' => $client->getId()]);
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

        // $entityManager->remove($client);
        $client->setEnabled(false);
        $client->setUpdatedAt(new \DateTime());
        $entityManager->flush();

        $this->addFlash('success', 'client.deleted_successfully');

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

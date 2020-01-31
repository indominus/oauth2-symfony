<?php
namespace App\Controller;

use App\Services\OAuth2\GenericProvider;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;

class HomepageController extends AbstractController
{

    /**
     *
     * @var string
     */
    private $apiUri = 'https://sandbox.openbank.icard.com';

    /**
     * @Route("/", name="homepage")
     *
     * @param Request $request
     * @param SessionInterface $session
     * @param GenericProvider $provider
     *
     * @return Response
     */
    public function index(Request $request, SessionInterface $session, GenericProvider $provider)
    {

        if ($accessToken = $session->get('accessToken', false)) {
            if (isset($accessToken['access_token'])) {
                return $this->indexAuthorized($request, $session);
            } else {
                $session->remove('accessToken');
            }
        }

        $form = $this->createFormBuilder([])
            ->add('authorize', SubmitType::class, [
                'label' => 'OAuth2 Authorize',
                'attr' => ['class' => 'btn btn-primary']
            ])
            ->getForm();

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {

            $url = $_ENV['CLIENT_GENERATE_ID'];

            try {
                $response = HttpClient::create(['http_version' => '1.1'])->request('POST', $_ENV['CLIENT_GENERATE_ID'])
                    ->getContent();
                $data = json_decode($response, true);
            } catch (ClientExceptionInterface $e) {
                $data = $e->getMessage();
            } catch (RedirectionExceptionInterface $e) {
                $data = $e->getMessage();
            } catch (ServerExceptionInterface $e) {
                $data = $e->getMessage();
            } catch (TransportExceptionInterface $e) {
                $data = $e->getMessage();
            }

            $oauthLink = $provider->getAuthorizationUrl([
                'scope' => 'ais.sandbox',
                'auth-id' => $data['auth-id']
            ]);

            $session->set('oauth2_state', $provider->getState());

            return $this->render('callback/index.html.twig', [
                    'oauth_url' => $oauthLink
            ]);
        }

        return $this->render('callback/index.html.twig', [
                'form' => $form->createView()
        ]);
    }

    /**
     * 
     * @param Request $request
     * @param SessionInterface $session
     */
    public function indexAuthorized(Request $request, SessionInterface $session)
    {

        $form = $this->createFormBuilder([])
            ->add('refresh', SubmitType::class, [
                'label' => 'Refresh token',
                'attr' => ['class' => 'btn btn-success']
            ])
            ->add('revoke', SubmitType::class, [
                'label' => 'Revoke token',
                'attr' => ['class' => 'btn btn-danger']
            ])
            ->getForm();

        $form->handleRequest($request);

        if ($form->isSubmitted()) {

            if ($form->get('refresh')->isClicked()) {
                return $this->refreshToken($request, $session);
            } else if ($form->get('revoke')->isClicked()) {
                return $this->revokeToken($request, $session);
            }

            return new RedirectResponse($this->generateUrl('homepage'));
        }

        return $this->render('callback/index.html.twig', [
                'form' => $form->createView()
        ]);
    }

    /**
     * 
     * @param Request $request
     * @param SessionInterface $session
     */
    public function refreshToken(Request $request, SessionInterface $session)
    {

        try {

            $client = HttpClient::create()->request('POST', sprintf('%s/token', $this->apiUri), [
                'body' => [
                    'grant_type' => 'refresh_token',
                    'client_id' => $_ENV['CLIENT_ID'],
                    'client_secret' => $_ENV['CLIENT_SECRET'],
                    'refresh_token' => $session->get('accessToken')['refresh_token']
                ]
            ]);

            $response = json_decode($client->getContent(), true);

            if (isset($response['access_token'])) {
                $session->set('accessToken', $response);

                $this->addFlash('success', 'Successfully regenerated accessToken');
            } else {
                $session->remove('accessToken');
                $this->addFlash('errors', $response['error'] ?? 'Error occured');
            }
        } catch (TransportExceptionInterface | Exception $e) {
            return new Response($e->getMessage());
        }

        return new RedirectResponse($this->generateUrl('homepage'));
    }

    /**
     * 
     * @param Request $request
     * @param SessionInterface $session
     */
    public function revokeToken(Request $request, SessionInterface $session)
    {
        $session->remove('accessToken');

        $this->addFlash('success', 'Successfully removed accessToken');

        return new RedirectResponse($this->generateUrl('homepage'));
    }
}

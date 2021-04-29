<?php

namespace App\Controller;

use Exception;
use App\Services\OAuth2\GenericProvider;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
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
            ->add('authorizeIng', SubmitType::class, [
                'label' => 'ING OAuth2 Authorize',
                'attr' => ['class' => 'btn btn-success mt-3']
            ])
            ->getForm();

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {

            if ($form->get('authorize')->isClicked()) {

                try {
                    $response = HttpClient::create(['http_version' => '1.1'])->request('POST', $_ENV['CLIENT_GENERATE_ID'], [
                        'verify_peer' => false,
                        'verify_host' => false,
                        'body' => ['client_id' => $_ENV['CLIENT_ID']]
                    ])->getContent();
                    $data = json_decode($response, true);
                } catch (ClientExceptionInterface | TransportExceptionInterface | ServerExceptionInterface | RedirectionExceptionInterface $e) {
                    $data = ['error' => $e->getMessage()];
                }

                if (isset($data['error'])) {
                    throw new \RuntimeException($data['error']);
                }

                if (empty($data['auth-id'])) {
                    throw new \RuntimeException('Error while getting auth-id');
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

            $url = 'https://api.ing.com/oauth2/token';
            $query = [
                'grant_types' => 'client_credentials',
                'scope' => urlencode(implode(',', [
                    'payment-accounts:balances:view',
                    'payment-accounts:transactions:view',
                    'payment-accounts:funds-availability:confirm',
                    'payment-requests:view',
                    'payment-requests:create',
                    'payment-requests:close',
                    'payment-requests:register',
                    'payment-accounts:orders:create',
                ]))
            ];
            $headers = [
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Date' => gmdate(),
                'Digest' => 'SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=',
                'Authorization' => implode(',', [
                    'Signature keyId="59E2D668957CBCA21C211EC2FFC035FD999BDA2F"',
                    'algorithm="rsa-sha256"',
                    'headers="(request-target) date digest"',
                    'signature="%s"'
                ])
            ];

            // Signature keyId="[CLIENT_ID or eIDAS_SERIAL_CA_IDENTIFIER]",algorithm="rsa-sha256", headers="(request-target) date digest", signature="[SIGNATURE_VALUE]"

            $oauthLink = 'https://api.ing.com/oauth2/token?';
        }

        return $this->render('callback/index.html.twig', [
            'form' => $form->createView()
        ]);
    }

    /**
     *
     * @param Request $request
     * @param SessionInterface $session
     * @return RedirectResponse|Response
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

            $client = HttpClient::create()->request('POST', $_ENV['CLIENT_ACCESS_TOKEN_ENDPOINT'], [
                'verify_peer' => false,
                'verify_host' => false,
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
                $this->addFlash('errors', $response['error'] ?? 'Error occur');
            }
        } catch (TransportExceptionInterface | Exception | ClientExceptionInterface | RedirectionExceptionInterface | ServerExceptionInterface $e) {
            $session->remove('accessToken');
            $this->addFlash('errors', $e->getMessage());
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

<?php

namespace EWZ\Bundle\RecaptchaBundle\Validator\Constraints;

use ReCaptcha\ReCaptcha;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use function is_callable;

class IsTrueValidator extends ConstraintValidator
{
    /**
     * @param bool                               $enabled
     * @param ReCaptcha                          $recaptcha
     * @param RequestStack                       $requestStack
     * @param bool                               $verifyHost
     * @param AuthorizationCheckerInterface|null $authorizationChecker
     * @param array                              $trustedRoles
     */
    public function __construct(
        /**
         * Enable recaptcha?
         */
        protected bool $enabled,
        /**
         * Recaptcha.
         */
        protected ReCaptcha $recaptcha,
        /**
         * Request Stack.
         */
        protected RequestStack $requestStack,
        /**
         * Enable serverside host check.
         */
        protected bool $verifyHost,
        /**
         * Authorization Checker.
         */
        protected ?AuthorizationCheckerInterface $authorizationChecker = null,
        /**
         * Trusted Roles.
         */
        protected array $trustedRoles = []
    )
    {
    }

    /**
     * {@inheritdoc}
     */
    public function validate($value, Constraint $constraint): void
    {
        // if recaptcha is disabled, always valid
        if (!$this->enabled) {
            return;
        }

        // if we have an authorized role
        if ($this->authorizationChecker
            && count($this->trustedRoles) > 0
            && $this->authorizationChecker->isGranted($this->trustedRoles)) {
            return;
        }

        if (is_callable($this->requestStack->getMainRequest(...))) {
            $request = $this->requestStack->getMainRequest();   // symfony 5.3+
        } else {
            $request = $this->requestStack->getMasterRequest();
        }

        $remoteip = $request->getClientIp();
        // define variable for recaptcha check answer
        $answer = $request->get('g-recaptcha-response');

        // Verify user response with Google
        $response = $this->recaptcha->verify($answer, $remoteip);

        if (!$response->isSuccess()) {
            $this->context->addViolation($constraint->message);
        }
        // Perform server side hostname check
        elseif ($this->verifyHost && $response->getHostname() !== $request->getHost()) {
            $this->context->addViolation($constraint->invalidHostMessage);
        }
    }
}

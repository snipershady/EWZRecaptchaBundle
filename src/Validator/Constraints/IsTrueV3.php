<?php

namespace EWZ\Bundle\RecaptchaBundle\Validator\Constraints;

use Attribute;
use Override;


/**
 * @Annotation
 * @Target("PROPERTY")
 */
#[Attribute(Attribute::TARGET_PROPERTY | Attribute::IS_REPEATABLE)]
class IsTrueV3 extends IsTrue
{
    /**
     * {@inheritdoc}
     */
    #[Override]
    public function validatedBy(): string
    {
        return 'ewz_recaptcha.v3.true';
    }
}

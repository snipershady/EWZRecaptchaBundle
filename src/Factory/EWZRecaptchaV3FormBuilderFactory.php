<?php

namespace EWZ\Bundle\RecaptchaBundle\Factory;

use EWZ\Bundle\RecaptchaBundle\Form\Type\EWZRecaptchaV3Type;
use EWZ\Bundle\RecaptchaBundle\Validator\Constraints\IsTrueV3;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\Form\FormBuilderInterface;

class EWZRecaptchaV3FormBuilderFactory
{
    public function __construct(private readonly FormFactoryInterface $builder)
    {
    }

    public function get(array $options = []) :FormBuilderInterface
    {
        $constraint = [
            'constraints' => [
                new IsTrueV3(),
                ],
            ];

        return $this->builder->createBuilder(EWZRecaptchaV3Type::class, null, array_merge($options, $constraint));
    }
}

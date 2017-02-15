<?php

namespace ApiBundle\Form;

use ApiBundle\Entity\User;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\FileType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\Extension\Core\Type\DateType;
use Symfony\Component\Form\Extension\Core\Type\CollectionType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;

use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class UserType extends AbstractType
{

    /**
     * @param FormBuilderInterface $builder
     * @param array $options
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder
            ->add('image', FileType::class, array('label' => 'Image, if any ', 'required' => false) )
            ->add('firstname',TextType::class)
            ->add('lastname',TextType::class)
            ->add('email', EmailType::class)
            ->add('dob', DateType::class)
            ->add('username', TextType::class)
            ->add('password', TextType::class, array('data' => ''))
            ->add('roles', CollectionType::class, array(
                  'entry_type'   => ChoiceType::class,
                  'entry_options'  => array(
                      'choices'  => array(
                          'ROLE_USER' => 'ROLE_USER',
                          'ROLE_API'  => 'ROLE_API',
                          ),
                  ),
            ));
    }

    /**
     * @param OptionsResolver $resolver
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefaults(array(
            'data_class' => User::class,
            'csrf_protection' => true
        ));
    }

    public function getName()
    {
        return 'user';
    }
}

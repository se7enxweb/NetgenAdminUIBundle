<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\Controller;

use eZ\Publish\API\Repository\Values\Content\Content;
use eZ\Publish\API\Repository\Values\Content\Location;
use eZ\Publish\Core\MVC\Symfony\View\ContentView;
use Netgen\Bundle\AdminUIBundle\Layouts\RelatedLayoutsLoader;
use Netgen\Layouts\API\Values\LayoutResolver\Rule;
use Netgen\Layouts\Layout\Resolver\LayoutResolverInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class LayoutsController extends Controller
{
    private LayoutResolverInterface $layoutResolver;
    private RelatedLayoutsLoader $relatedLayoutsLoader;

    public function __construct(
        LayoutResolverInterface $layoutResolver,
        RelatedLayoutsLoader $relatedLayoutsLoader
    ) {
        $this->layoutResolver = $layoutResolver;
        $this->relatedLayoutsLoader = $relatedLayoutsLoader;
    }

    /**
     * Renders a template that shows all layouts applied to provided location.
     */
    public function showLocationLayouts(int|string $locationId): Response
    {
        $repository = $this->getRepository();
        $location = $repository->getLocationService()->loadLocation((int)$locationId);
        $content = $repository->getContentService()->loadContent($location->contentInfo->id);

        $request = $this->createRequest($content, $location);
        $rules = $this->layoutResolver->resolveRules($request, ['ez_content_type']);
        $rulesOneOnOne = [];

        foreach ($rules as $rule) {
            $rulesOneOnOne[$rule->getId()->toString()] = $this->isRuleOneOnOne($location, $rule);
        }

        return $this->render(
            '@NetgenAdminUI/layouts/location_layouts.html.twig',
            [
                'rules' => $rules,
                'rules_one_on_one' => $rulesOneOnOne,
                'related_layouts' => $this->relatedLayoutsLoader->loadRelatedLayouts($location),
                'location' => $location,
            ]
        );
    }

    /**
     * Creates the request used for fetching the mappings applied to provided content and location.
     */
    protected function createRequest(Content $content, Location $location): Request
    {
        $request = Request::create('');
        $request->attributes->set('content', $content);
        $request->attributes->set('location', $location);

        if (interface_exists('eZ\Publish\Core\MVC\Symfony\View\ContentValueView')) {
            $contentView = new ContentView();
            $contentView->setLocation($location);
            $contentView->setContent($content);
            $request->attributes->set('view', $contentView);
        }

        return $request;
    }

    /**
     * Checks if a rule applies to exactly one location (one-on-one mapping).
     */
    protected function isRuleOneOnOne(Location $location, Rule $rule): bool
    {
        // Only single-target rules can be one-on-one
        if (count($rule->getTargets()) !== 1) {
            return false;
        }

        $target = $rule->getTargets()[0];

        // Check if target is exactly this location
        if ($target->getTargetType()::getType() === 'ez_location') {
            if ((int)$target->getValue() === (int)$location->id) {
                return true;
            }
        }

        // Check if target is the content of this location
        if ($target->getTargetType()::getType() === 'ez_content') {
            if ((int)$target->getValue() === (int)$location->contentId) {
                return true;
            }
        }

        return false;
    }
}

<?php
/**
 * @package htmlpurifier
 * @subpackage tests
 */
class HtmlPurifierSanitiserTest extends SapphireTest {

	/* Tests for filtering out unwanted elements or attributes */
	static $base_tests = array(
		array(
			'p,strong',
			'<p>Leave Alone</p><div>Strip parent<strong>But keep children</strong> in order</div>',
			'<p>Leave Alone</p>Strip parent<strong>But keep children</strong> in order',
			'Non-whitelisted elements are stripped, but children are kept'
		),
		array(
			'p,strong',
			'<div>A <strong>B <div>Nested elements are still filtered</div> C</strong> D</div>',
			'A <strong>B Nested elements are still filtered C</strong> D',
			'Non-whitelisted elements are stripped even when children of non-whitelisted elements'
		),
		array(
			'p',
			'<p>Keep</p><script>Strip <strong>including children</strong></script>',
			'<p>Keep</p>',
			'Non-whitelisted script elements are totally stripped, including any children'
		),
		array(
			'p[id]',
			'<p id="keep" bad="strip">Test</p>',
			'<p id="keep">Test</p>',
			'Non-whitelisted attributes are stripped'
		)
	);

	/* XSS filtering tests */
	static $xss_tests = array(
		array(
			'a[href]',
			'<a href="test.html">Regular links work</a><a href="javascript:alert(1)">Javascript links dont</a>',
			'<a href="test.html">Regular links work</a><a>Javascript links dont</a>',
			'Javascript in href links is stripped'
		)
	);

	protected function runSanitisationTest($test) {
		list($validElements, $input, $output, $desc) = $test;

		$config = HtmlEditorConfig::get('htmleditorsanitisertest');
		$config->setOptions(array('valid_elements' => $validElements));

		$sanitiser = new HtmlPurifierSanitiser($config);
		$htmlValue = Injector::inst()->create('HTMLValue', $input);
		$sanitiser->sanitise($htmlValue);

		$this->assertEquals($output, $htmlValue->getContent(), $desc);
	}

	public function testTinyMCESanitisation() {
		foreach(self::$base_tests as $test) $this->runSanitisationTest($test);
		foreach(self::$xss_tests as $test) $this->runSanitisationTest($test);
	}
}
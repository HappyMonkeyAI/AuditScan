<?php

class API {
    public function hello() {
        return ["message" => "Hello, World!"];
    }
}

$api = new API();
echo json_encode($api->hello());

?>

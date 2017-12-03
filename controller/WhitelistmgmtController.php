<?php
/**
 * Created by PhpStorm.
 * User: suraj
 * Date: 11/07/2016
 * Time: 8:28 AM
 */
/**
 * @version     2.0 +
 * @package       Open Source Excellence Security Suite
 * @subpackage    Centrora Security Firewall
 * @subpackage    Open Source Excellence WordPress Firewall
 * @author        Open Source Excellence {@link http://www.opensource-excellence.com}
 * @author        Created on 01-Jun-2013
 * @license GNU/GPL http://www.gnu.org/copyleft/gpl.html
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *  @Copyright Copyright (C) 2008 - 2012- ... Open Source Excellence
 */
namespace App\Controller;

if (!defined('OSE_FRAMEWORK') && !defined('OSEFWDIR') && !defined('_JEXEC'))
{
    die('Direct Access Not Allowed');
}
class WhitelistmgmtController extends \App\Base {

    public function action_getEntityList() {
        $results = $this->model->getEntityList();
        $this->model->returnJSON($results);
    }
    public function action_addEntity()
    {
        $this->model->loadRequest();
        $entity_type = $this->model->getVar('entitytype', null);
        $request_type = $this->model->getVar('requesttype', null);
        $entity_name = $this->model->getVar('entityname', null);
        $status = $this->model->getVar('statusfield', null);
        $result = $this->model->addEntity($entity_name,$entity_type,$request_type,$status);
        $this->model->returnJSON($result);
    }

    public function action_scan()
    {
        $ids = $this->model->getVar('ids', null);
        $idarray = $this->model->JSON_decode($ids);
        $results = $this->model->scan($idarray);
        $this->model->returnJSON($results);
    }

    public function action_whitelist()
    {
        $ids = $this->model->getVar('ids', null);
        $idarray = $this->model->JSON_decode($ids);
        $results = $this->model->whitelist($idarray);
        $this->model->returnJSON($results);
    }

    public function action_filter()
    {
        $ids = $this->model->getVar('ids', null);
        $idarray = $this->model->JSON_decode($ids);
        $results = $this->model->filter($idarray);
        $this->model->returnJSON($results);
    }


    public function action_clearAll()
    {
        $this->model->loadRequest();
        $result = $this->model->clearAll();
        $this->model->returnJSON($result);
    }

    public function action_deleteItem()
    {
        $this->model->loadRequest();
        $idlist = $this->model->getVar('ids', null);
        $idarray = $this->model->JSON_decode($idlist);
        $result = $this->model->deleteItem($idarray);
        $this->model->returnJSON($result);
    }

    public function action_loadDefaultVariables()
    {
        $this->model->loadRequest();
        $type =  $this->model->getVar('type', null);
        $result = $this->model->loadDefaultVariables($type);
        $this->model->returnJSON($result);
    }
    public function action_importVariables()
    {
        $this->model->loadRequest();
        $result = $this->model->importVariables();
        $this->model->returnJSON($result);
    }
    public function action_defaultWhiteListVariablesV7()
    {
        $this->model->loadRequest();
        $result = $this->model->defaultWhiteListVariablesV7();
        $this->model->returnJSON($result);
    }
}
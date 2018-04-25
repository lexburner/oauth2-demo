package moe.cnkirito.security.oauth2.code.endpoint;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * @author 徐靖峰[OF2938]
 * company qianmi.com
 * Date 2018-04-25
 */
public class InMemoryQQDatabase {

    public static Map<String,QQAccount> database;

    static {
        database = new HashMap<>();
        database.put("250577914",new QQAccount().qq("250577914").nickName("鱼非渔").level("54"));
        database.put("920129126",new QQAccount().qq("920129126").nickName("下一秒升华").level("31"));

        QQAccount qqAccount1 = database.get("250577914");
        qqAccount1.fans(new ArrayList<>());
        for(int i=0;i<5;i++){
            qqAccount1.fans().add(new QQAccount().qq("1000000"+i).nickName("fan"+i).level(i+"") );
        }

        QQAccount qqAccount2 = database.get("920129126");
        qqAccount2.fans(new ArrayList<>());
        for(int i=0;i<3;i++){
            qqAccount2.fans().add(new QQAccount().qq("2000000"+i).nickName("fan"+i).level(i+"") );
        }
    }

}

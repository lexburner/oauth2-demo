package moe.cnkirito.security.oauth2.code.endpoint;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.Accessors;

import java.util.List;

/**
 * @author 徐靖峰[OF2938]
 * company qianmi.com
 * Date 2018-04-25
 */
@Data
@EqualsAndHashCode(of = "qq")
@ToString(exclude = "fans")
@Builder
public class QQAccount {

    private String qq;
    private String nickName;
    private String level;
    private List<QQAccount> fans;

}

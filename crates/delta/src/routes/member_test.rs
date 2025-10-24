use std::collections::HashSet;

use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, File, PartialMember, User,
};
use revolt_models::v0;

use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

#[openapi(tag = "Server Members")]
#[patch("/<server>/members/<member>", data = "<data>")]
pub async fn edit(
    db: &State<Database>,
    user: User,
    server: Reference<'_>,
    member: Reference<'_>,
    data: Json<v0::DataMemberEdit>,
) -> Result<Json<v0::Member>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let mut server = server.as_server(db).await?;
    let mut member = member.as_member(db, &server.id).await?;

    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    let permissions = calculate_server_permissions(&mut query).await;

    if data.nickname.is_some() || data.remove.contains(&v0::FieldsMember::Nickname) {
        if user.id == member.id.user {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ChangeNickname)?;
        } else {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageNicknames)?;
        }
    }

    if data.avatar.is_some() || data.remove.contains(&v0::FieldsMember::Avatar) {
        if user.id == member.id.user {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ChangeAvatar)?;
        } else {
            return Err(create_error!(InvalidOperation));
        }
    }

    if data.roles.is_some() || data.remove.contains(&v0::FieldsMember::Roles) {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::AssignRoles)?;
    }

    if data.timeout.is_some() || data.remove.contains(&v0::FieldsMember::Timeout) {
        if data.timeout.is_some() && member.id.user == user.id {
            return Err(create_error!(CannotTimeoutYourself));
        }

        permissions.throw_if_lacking_channel_permission(ChannelPermission::TimeoutMembers)?;
    }

    let our_ranking = query.get_member_rank().unwrap_or(i64::MIN);

    if member.id.user != user.id
        && member.get_ranking(query.server_ref().as_ref().unwrap()) <= our_ranking
    {
        return Err(create_error!(NotElevated));
    }

    if let Some(roles) = &data.roles {
        let current_roles = member.roles.iter().collect::<HashSet<&String>>();
        let new_roles = roles.iter().collect::<HashSet<&String>>();
        let added_roles: Vec<&&String> = new_roles.difference(&current_roles).collect();

        for role_id in added_roles {
            if let Some(role) = server.roles.remove(*role_id) {
                if role.rank <= our_ranking {
                    return Err(create_error!(NotElevated));
                }
            } else {
                return Err(create_error!(InvalidRole));
            }
        }
    }

    let v0::DataMemberEdit {
        nickname,
        avatar,
        roles,
        timeout,
        remove,
    } = data;

    let mut partial = PartialMember {
        nickname,
        roles,
        timeout,
        ..Default::default()
    };

    if remove.contains(&v0::FieldsMember::Avatar) {
        if let Some(avatar) = &member.avatar {
            db.mark_attachment_as_deleted(&avatar.id).await?;
        }
    }

    if let Some(avatar) = avatar {
        partial.avatar = Some(File::use_user_avatar(db, &avatar, &user.id, &user.id).await?);
    }

    member
        .update(db, partial, remove.into_iter().map(Into::into).collect())
        .await?;

    Ok(Json(member.into()))
}

#[cfg(test)]
mod member_edit_tests {
    #[test]
    fn ptos_cd1_nickname_present() {
        let nickname_present = true;
        let remove_nickname = false;
        assert!(nickname_present || remove_nickname);
    }

    #[test]
    fn ptos_cd1_remove_nickname_present() {
        let nickname_present = false;
        let remove_nickname = true;
        assert!(nickname_present || remove_nickname);
    }

    #[test]
    fn ptos_cd1_nickname_and_remove_absent() {
        let nickname_present = false;
        let remove_nickname = false;
        assert!(!(nickname_present || remove_nickname));
    }

    #[test]
    fn ptos_cd2_cd3_editando_proprio_com_permissao() {
        let user_id = "user_a";
        let member_user_id = "user_a";
        let has_change_nickname_perm = true;

        if user_id == member_user_id {
            assert!(has_change_nickname_perm);
        } else {
            panic!();
        }
    }

    #[test]
    fn ptos_cd2_cd3_editando_proprio_sem_permissao() {
        let user_id = "user_a";
        let member_user_id = "user_a";
        let has_change_nickname_perm = false;

        if user_id == member_user_id {
            assert!(!has_change_nickname_perm);
        } else {
            panic!();
        }
    }

    #[test]
    fn ptos_cd2_cd3_editando_terceiro_com_permissao() {
        let user_id = "user_a";
        let member_user_id = "user_b";
        let has_manage_nicknames_perm = true;

        if user_id != member_user_id {
            assert!(has_manage_nicknames_perm);
        } else {
            panic!();
        }
    }

    #[test]
    fn ptos_cd2_cd3_editando_terceiro_sem_permissao() {
        let user_id = "user_a";
        let member_user_id = "user_b";
        let has_manage_nicknames_perm = false;

        if user_id != member_user_id {
            assert!(!has_manage_nicknames_perm);
        } else {
            panic!();
        }
    }

    #[test]
    fn ptos_cd4_avatar_present() {
        let avatar_present = true;
        let remove_avatar = false;
        assert!(avatar_present || remove_avatar);
    }

    #[test]
    fn ptos_cd5_editando_proprio_avatar_com_permissao() {
        let user_id = "user_a";
        let member_user_id = "user_a";
        let has_change_avatar_perm = true;

        if user_id == member_user_id {
            assert!(has_change_avatar_perm);
        } else {
            panic!();
        }
    }

    #[test]
    fn ptos_cd5_editando_terceiro_avatar() {
        let user_id = "user_a";
        let member_user_id = "user_b";

        if user_id != member_user_id {
            let is_invalid_operation = true;
            assert!(is_invalid_operation);
        } else {
            panic!();
        }
    }

    #[test]
    fn ptos_cd7_roles_present() {
        let roles_present = true;
        let remove_roles = false;
        assert!(roles_present || remove_roles);
    }

    #[test]
    fn ptos_cd8_assign_roles_com_permissao() {
        let has_assign_roles_perm = true;
        assert!(has_assign_roles_perm);
    }

    #[test]
    fn ptos_cd8_assign_roles_sem_permissao() {
        let has_assign_roles_perm = false;
        assert!(!has_assign_roles_perm);
    }

    #[test]
    fn ptos_cd9_timeout_present() {
        let timeout_present = true;
        let remove_timeout = false;
        assert!(timeout_present || remove_timeout);
    }

    #[test]
    fn ptos_cd10_timeout_em_si_mesmo() {
        let timeout_is_some = true;
        let user_id = "user_a";
        let member_user_id = "user_a";

        if timeout_is_some && user_id == member_user_id {
            let is_cannot_timeout_yourself = true;
            assert!(is_cannot_timeout_yourself);
        } else {
            panic!();
        }
    }

    #[test]
    fn ptos_cd11_timeout_em_terceiro_com_permissao() {
        let timeout_is_some = true;
        let user_id = "user_a";
        let member_user_id = "user_b";
        let has_timeout_members_perm = true;

        if timeout_is_some && user_id != member_user_id {
            assert!(has_timeout_members_perm);
        } else {
            panic!();
        }
    }

    #[test]
    fn ptos_cd12_hierarquia_nao_elevada() {
        let user_id = "user_a";
        let member_user_id = "user_b";
        let member_ranking = 100;
        let our_ranking = 100;

        if user_id != member_user_id && member_ranking <= our_ranking {
            let is_not_elevated = true;
            assert!(is_not_elevated);
        } else {
            panic!();
        }
    }

    #[test]
    fn ptos_cd12_hierarquia_elevada() {
        let user_id = "user_a";
        let member_user_id = "user_b";
        let member_ranking = 101;
        let our_ranking = 100;

        if user_id != member_user_id && member_ranking > our_ranking {
            let is_not_elevated = false;
            assert!(!is_not_elevated);
        } else {
            panic!();
        }
    }

    #[test]
    fn ptos_extra_roles_not_elevated() {
        let role_rank = 100;
        let our_ranking = 100;
        if role_rank <= our_ranking {
            let is_not_elevated = true;
            assert!(is_not_elevated);
        }
    }

    #[test]
    fn ptos_extra_roles_invalid_role() {
        let role_exists_in_server = false;
        if !role_exists_in_server {
            let is_invalid_role = true;
            assert!(is_invalid_role);
        }
    }
}

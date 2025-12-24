package in.agampal.Authify.Repository;

import in.agampal.Authify.Entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Optional<UserEntity>findByEmail(String email);

   Boolean existsByEmail(String email);
}
